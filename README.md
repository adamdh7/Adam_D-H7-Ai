# Adam_D'H7 — OpenRouter Proxy + Telegram Bot

This repository contains an HTTP proxy for OpenRouter (chat completions) and optional support for a Telegram bot. It's designed to run on Node.js (ESM).

> **Note:** This repo does not include `index.mjs` / `index.js` by default in case you want to paste the versions provided earlier. Add those files to run the proxy and bot.

---

## Requirements
- Node.js ≥ 18 (recommended)  
- npm (bundled with Node)  
- (Optional) `pm2` to run processes in background: `npm install -g pm2`.

---

## Important files
- `index.mjs` — Proxy / API (ESM) — **required** to run the proxy.  
- `index.js` — Telegram bot (optional) — run if you want the Telegram bot.  
- `package.json` — scripts and dependencies.  
- `.env` — environment variables (DO NOT commit to public repos).  
- `user.json`, `sessions.json` — created automatically at first run.

---

## Example `.env`
Create a `.env` file in the repository root (do **not** push to Git):
pm2 start index.mjs --name adam-proxy
pm2 start index.js --name adam-bot    # if using the bot
pm2 logs adam-proxy
---

# package.json


{
  "name": "adam-dh7",
  "version": "1.0.0",
  "description": "Adam_D'H7 - OpenRouter proxy + Telegram bot",
  "type": "module",
  "main": "index.mjs",
  "engines": {
    "node": ">=18"
  },
  "scripts": {
    "start:proxy": "node index.mjs",
    "start:bot": "node index.js",
    "start": "npm run start:proxy",
    "dev:proxy": "nodemon --watch . --ext js,mjs,json --signal SIGTERM index.mjs",
    "dev:bot": "nodemon --watch . --ext js,mjs,json --signal SIGTERM index.js"
  },
  "dependencies": {
    "cors": "^2.8.5",
    "dotenv": "^16.6.1",
    "express": "^4.18.2",
    "node-fetch": "^3.3.1",
    "telegraf": "^4.12.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  },
  "keywords": [],
  "author": "",
  "license": "ISC"
}
