/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        discord: {
          bg: '#36393f',
          sidebar: '#2f3136',
          channels: '#202225',
          chat: '#36393f',
          input: '#40444b',
          accent: '#5865f2',
          green: '#3ba55c',
          red: '#ed4245',
        }
      }
    },
  },
  plugins: [],
}
