use tauri::Manager;
use tauri_plugin_single_instance::init as single_instance;

// Makes an outbound HTTP GET from the exit relay's machine, bypassing WebView CORS.
// Response is capped at 200 KB to keep relay DataChannel traffic manageable.
#[tauri::command]
async fn relay_fetch(url: String) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
             AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/120.0.0.0 Safari/537.36",
        )
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    let capped = &bytes[..bytes.len().min(204_800)];
    Ok(String::from_utf8_lossy(capped).into_owned())
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    open::that(url).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(single_instance(|app, _args, _cwd| {
            // A second instance tried to launch — bring the existing window to front and exit.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .invoke_handler(tauri::generate_handler![relay_fetch, open_url])
        .setup(|app| {
            // Register the app to launch on Windows startup via the current-user Run key.
            // Uses the path of the running executable so it always points to the installed copy.
            #[cfg(target_os = "windows")]
            {
                if let Ok(exe) = std::env::current_exe() {
                    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
                    if let Ok((key, _)) = hkcu.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run") {
                        let _ = key.set_value("BunChat", &exe.to_string_lossy().to_string());
                    }
                }
            }
            // Start minimized so the app sits quietly in the taskbar on auto-launch
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.minimize();
            }
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
