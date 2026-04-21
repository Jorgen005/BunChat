/// <reference types="vite/client" />

declare module 'trystero' {
  export function joinRoom(config: any, roomId: string): any;
  export const selfId: string;
  // Add more if you get other errors later
}