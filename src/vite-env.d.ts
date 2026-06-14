/// <reference types="vite/client" />

declare module 'trystero' {
  export function joinRoom(config: any, roomId: string): any;
  export const selfId: string;
  // Add more if you get other errors later
}

// Self-hosted font CSS (side-effect imports, no type declarations of their own).
declare module '@fontsource-variable/geist';
declare module '@fontsource-variable/geist-mono';