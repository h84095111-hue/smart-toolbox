<div align="center">
  <img src="docs/assets/smart-toolbox-hero.svg" alt="Smart Toolbox Pro — everyday utilities in one workspace" width="100%" />

  <h1>Smart Toolbox</h1>
  <p><strong>Everyday utilities. One beautiful workspace.</strong></p>
  <p>A privacy-first collection of practical tools that run directly in your browser.</p>

  ![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue?logo=typescript)
  ![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
  ![Vite](https://img.shields.io/badge/Vite-6-646CFF?logo=vite)
  ![License](https://img.shields.io/badge/License-MIT-green)
</div>


## 🖥️ Native desktop application (PyQt6)

A cross-platform desktop edition is now available in the [desktop folder](desktop/). It uses Python + PyQt6 and includes the same 12 utilities in a native GUI for **Windows, macOS, and Linux**.

Quick start in powershell:

```bash
cd desktop
python -m venv .venv
# Activate the environment (see desktop/README.md)
python -m pip install -r requirements.txt
python main.py
```

Packaging scripts and detailed instructions are in [desktop/BUILDING.md](desktop/BUILDING.md). Build separately on each target OS; PyInstaller does not cross-compile. GitHub Actions is configured to create OS-specific build artifacts when the desktop files change.

## ✨ What's inside

| Tool | What it does |
|---|---|
| 🔐 Password generator | Creates random passwords with adjustable length and character sets using the Web Crypto API. |
| ▦ QR code generator | Turns text or links into downloadable QR-code PNGs. |
| `{}` JSON formatter | Validates, pretty-prints and minifies JSON. |
| ⇄ Base64 converter | Encodes and decodes UTF-8 text. |
| 🔗 URL encoder | Encodes and decodes URL components. |
| # SHA-256 | Hashes text with the browser's Web Crypto API. |
| Aa Text toolkit | Counts words, characters and lines; changes case and cleans whitespace. |
| ↔ Unit converter | Converts length, weight and temperature. |
| 🆔 UUID generator | Creates random version-4 identifiers with Web Crypto. |
| 🎨 Color converter | Shows HEX, RGB and HSL values for a selected color. |
| ◷ Timestamp converter | Converts Unix timestamps (seconds) to UTC dates. |
| 📝 Markdown helper | Drafts and previews basic Markdown formatting. |

## 🚀 Install and run

**Requirements:** Node.js 18.18 or newer and npm.

```bash
git clone https://github.com/h84095111-hue/smart-toolbox.git
cd smart-toolbox
npm install
npm run dev
```

Open the local address printed by Vite (normally `http://localhost:5173`).

### Build for production

```bash
npm run build
npm run preview
```

The production-ready website is generated in `dist/`. You can host that folder on GitHub Pages, Netlify, Vercel, or any static web host.

## 📖 How to use

1. Open Smart Toolbox in your browser.
2. Choose a tool card, or search by its name or category.
3. Enter or paste your input.
4. Select the action (for example **Format JSON** or **Generate password**).
5. Copy the result or download it when a download option is available.

Tool-specific walkthroughs and troubleshooting are in [`docs/USAGE.md`](docs/USAGE.md). Setup help is in [`docs/INSTALLATION.md`](docs/INSTALLATION.md).

## 🖼️ Preview image

The banner above is product artwork, not a screenshot of the running interface.

## 🔒 Privacy and security

- Utility processing happens in your browser; the app has no application server or account system.
- Password generation uses `crypto.getRandomValues()`.
- SHA-256 uses the browser's Web Crypto API.
- The app does not intentionally save tool inputs or generated passwords.
- Avoid entering secrets into any website on a shared or compromised device.

## 🧰 Tech stack

React 18 · TypeScript · Vite · Lucide React · `qrcode.react` · Web Crypto API

## 🗂 Project structure

```text
smart-toolbox/
├── .github/workflows/ci.yml
├── docs/
│   ├── assets/smart-toolbox-hero.png
│   ├── INSTALLATION.md
│   ├── USAGE.md
│   └── VIDEO-GUIDE.md
├── src/
│   ├── App.tsx
│   ├── main.tsx
│   └── style.css
├── index.html
├── package.json
└── README.md
```

## 🤝 Contributing

Issues and pull requests are welcome. Please run `npm run build` before submitting changes and describe any new browser permissions or data handling.

## 📄 License

MIT — see [`LICENSE`](LICENSE).
