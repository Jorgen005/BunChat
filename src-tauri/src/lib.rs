use tauri::Manager;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

#[cfg(not(feature = "dev-build"))]
use tauri_plugin_single_instance::init as single_instance;

// Largest response we will pull back over the relay DataChannel.
const MAX_RESPONSE_BYTES: usize = 204_800; // 200 KB
// Cap redirect chains so a hostile site cannot keep us hopping forever.
const MAX_REDIRECTS: usize = 5;

// Resolves the URL's host and returns the concrete socket addresses we are
// allowed to connect to. Every resolved address must be globally routable so a
// hostname that points at loopback / RFC1918 / link-local space (e.g. the cloud
// metadata endpoint 169.254.169.254) is rejected *before* any connection is made.
//
// The returned addresses are later pinned into the reqwest client via
// `.resolve()`, so reqwest connects to exactly the IPs we validated — closing the
// DNS-rebinding window between this check and the actual request.
fn resolve_and_validate(parsed: &url::Url) -> Result<Vec<SocketAddr>, String> {
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("Only http/https URLs are permitted".to_string()),
    }

    let host = parsed.host_str().ok_or("Missing host")?;

    if host.eq_ignore_ascii_case("localhost") {
        return Err("Blocked host".to_string());
    }

    let port = parsed
        .port_or_known_default()
        .ok_or("Could not determine port")?;

    // Strip IPv6 brackets so the address parses correctly.
    let bare = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };

    // Literal IP in the URL — validate it directly, no DNS needed.
    if let Ok(ip) = bare.parse::<IpAddr>() {
        if !is_globally_routable(ip) {
            return Err("Private or reserved addresses are not allowed".to_string());
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    // Hostname — resolve via the system resolver and validate every answer.
    let resolved: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| "DNS resolution failed".to_string())?
        .collect();

    if resolved.is_empty() {
        return Err("Host did not resolve to any address".to_string());
    }

    for sa in &resolved {
        if !is_globally_routable(sa.ip()) {
            return Err("Host resolves to a private or reserved address".to_string());
        }
    }

    Ok(resolved)
}

fn is_globally_routable(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_loopback()          // 127.0.0.0/8
                && !v4.is_private()    // 10/8, 172.16/12, 192.168/16
                && !v4.is_link_local() // 169.254/16  (AWS/GCP metadata)
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !v4.is_multicast()
                && !v4.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
                && v4.octets()[0] != 0     // 0.0.0.0/8
        }
        std::net::IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && (v6.segments()[0] & 0xfe00 != 0xfc00) // fc00::/7 ULA
                && (v6.segments()[0] & 0xffc0 != 0xfe80) // fe80::/10 link-local
                // Reject IPv4-mapped (::ffff:0:0/96) so a mapped private v4
                // address can't sneak past the v6 checks.
                && v6.to_ipv4_mapped().map_or(true, is_globally_routable_v4)
        }
    }
}

fn is_globally_routable_v4(v4: std::net::Ipv4Addr) -> bool {
    is_globally_routable(std::net::IpAddr::V4(v4))
}

// Makes an outbound HTTP GET from the exit relay's machine, bypassing WebView CORS.
//
// Redirects are followed manually (not by reqwest) so that the target of every
// hop is re-validated against the SSRF rules above — a public URL cannot 30x its
// way to localhost or a metadata endpoint. The response body is capped to keep
// relay DataChannel traffic manageable.
#[tauri::command]
async fn relay_fetch(url: String) -> Result<String, String> {
    let mut current = url::Url::parse(&url).map_err(|_| "Invalid URL".to_string())?;

    for _hop in 0..=MAX_REDIRECTS {
        let addrs = resolve_and_validate(&current)?;
        let host = current
            .host_str()
            .ok_or("Missing host")?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();

        let mut builder = reqwest::Client::builder()
            .user_agent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                 AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/120.0.0.0 Safari/537.36",
            )
            .timeout(std::time::Duration::from_secs(20))
            // We validate and follow redirects ourselves.
            .redirect(reqwest::redirect::Policy::none());

        // Pin DNS to the exact addresses we just validated (anti-rebinding).
        for sa in &addrs {
            builder = builder.resolve(&host, *sa);
        }

        let client = builder.build().map_err(|e| e.to_string())?;
        let resp = client
            .get(current.as_str())
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or("Redirect without a Location header")?;
            // Resolve relative redirects against the current URL.
            current = current
                .join(location)
                .map_err(|_| "Invalid redirect target".to_string())?;
            continue;
        }

        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        let capped = &bytes[..bytes.len().min(MAX_RESPONSE_BYTES)];
        return Ok(String::from_utf8_lossy(capped).into_owned());
    }

    Err("Too many redirects".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init());

    // Dev builds allow multiple instances so you can test messaging between windows.
    // Production enforces single-instance and focuses the existing window instead.
    #[cfg(not(feature = "dev-build"))]
    let builder = builder.plugin(single_instance(|app, _args, _cwd| {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.set_focus();
        }
    }));

    builder
        .invoke_handler(tauri::generate_handler![relay_fetch])
        .setup(|app| {
            // NOTE: we intentionally do NOT register the app to run at Windows
            // startup. Auto-starting at boot would make the machine relay other
            // people's traffic silently, without the user actively choosing to be
            // online infrastructure. Relaying should only happen while the user
            // has the app open.
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
