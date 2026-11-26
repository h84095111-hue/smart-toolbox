# Installation guide

## Option A — run from source (recommended for development)

1. Install Node.js 18.18+ from <https://nodejs.org/>. npm is included with Node.js.
2. Download this repository as a ZIP from GitHub and extract it, or clone it:
   ```bash
   git clone https://github.com/h84095111-hue/smart-toolbox.git
   cd smart-toolbox
   ```
3. Open a terminal in the project directory.
4. Install packages:
   ```bash
   npm install
   ```
5. Start the local development server:
   ```bash
   npm run dev
   ```
6. Open the URL Vite prints, usually <http://localhost:5173>.

Stop the server with `Ctrl+C` in the terminal.

## Option B — build a deployable website

```bash
npm install
npm run build
```

Upload the generated `dist/` directory to a static hosting provider. No database, API key, or backend server is required for the current toolset.

## Troubleshooting

- **`node` or `npm` not found:** close and reopen the terminal after installing Node.js; check `node --version` and `npm --version`.
- **Port 5173 is busy:** Vite normally offers another available local port in the terminal output.
- **Dependency install fails:** check your internet connection and retry `npm install`.
- **Clipboard access is blocked:** use the app on `localhost` or a secure HTTPS site and grant clipboard permission if your browser asks.
- **QR download does not start:** allow downloads for the site in your browser.
