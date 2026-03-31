# DepScan — Cross-Repo Dependency Explorer

> Search your dependencies across every GitHub repo, instantly.

DepScan is a zero-backend static web app that connects to your GitHub account and aggregates dependency data (SBOMs) across **all** your repositories into a single, searchable interface. Perfect for answering the critical question during supply-chain incidents: _"Which of my repos are affected and what versions are they running?"_

![Landing Page](https://img.shields.io/badge/Status-v1.0-06b6d4?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-8b5cf6?style=flat-square)
![Backend](https://img.shields.io/badge/Backend-None-10b981?style=flat-square)

---

## ✨ Features

- **Instant Search** — Type a package name and see every repo using it
- **Version Drift Detection** — Spot packages with inconsistent versions across repos
- **Multi-Ecosystem** — npm, pip, Maven, Go, Cargo, NuGet, and more
- **Repo Detail Panel** — Drill into any repo's full dependency list
- **Smart Caching** — localStorage cache with 1hr TTL + ETag support
- **Zero Backend** — Static site on GitHub Pages + tiny Cloudflare Worker for OAuth only
- **Privacy First** — Token in `sessionStorage` only (cleared on tab close), no data stored server-side

---

## 🚀 Setup

### Prerequisites

- A GitHub account
- A free [Cloudflare account](https://dash.cloudflare.com/sign-up) (for the OAuth proxy worker)
- Node.js installed (for the Wrangler CLI)

### Step 1: Create a GitHub OAuth App

1. Go to [GitHub Developer Settings → OAuth Apps](https://github.com/settings/developers)
2. Click **"New OAuth App"**
3. Fill in:

   | Field | Value |
   |---|---|
   | Application name | `DepScan` |
   | Homepage URL | `https://<your-username>.github.io/centerdeps` |
   | Authorization callback URL | `https://<your-username>.github.io/centerdeps/oauth-callback.html` |

4. Click **Register application**
5. Copy the **Client ID**
6. Click **"Generate a new client secret"** and copy it immediately

### Step 2: Deploy the Cloudflare Worker

```bash
# Install Wrangler
npm install -g wrangler

# Authenticate
wrangler login

# Create a new worker project
mkdir oauth-proxy && cd oauth-proxy
wrangler init . --type javascript

# Copy the worker code from worker/oauth-proxy.js in this repo
# into src/index.js of the worker project

# Set secrets
wrangler secret put GITHUB_CLIENT_ID      # paste your Client ID
wrangler secret put GITHUB_CLIENT_SECRET   # paste your Client Secret
wrangler secret put ALLOWED_ORIGIN         # paste: https://<your-username>.github.io

# Deploy
wrangler deploy
```

Note the worker URL from the output (e.g. `https://oauth-proxy.xxx.workers.dev`).

### Step 3: Configure the App

Edit two files to add your values:

**`app.js`** — Update the `CONFIG` object:
```js
const CONFIG = {
  GITHUB_CLIENT_ID:  'Ov23li...',                          // your Client ID
  OAUTH_PROXY_URL:   'https://oauth-proxy.xxx.workers.dev', // your Worker URL
  // ...
};
```

**`oauth-callback.html`** — Update:
```js
const OAUTH_PROXY_URL = 'https://oauth-proxy.xxx.workers.dev';
```

### Step 4: Deploy to GitHub Pages

```bash
# Push to GitHub
git add -A
git commit -m "Initial DepScan deployment"
git remote add origin https://github.com/<your-username>/centerdeps.git
git push -u origin main
```

Then go to your repo on GitHub → **Settings** → **Pages** → Source: `main` / `/ (root)` → Save.

Visit `https://<your-username>.github.io/centerdeps/` after a minute.

---

## 🏗 Architecture

```
┌─────────────┐     ┌──────────────┐     ┌────────────────────┐
│   Browser    │────▶│ GitHub OAuth │────▶│ Cloudflare Worker  │
│  (DepScan)   │◀────│              │◀────│ (token exchange)   │
└──────┬───────┘     └──────────────┘     └────────────────────┘
       │
       │  GitHub REST API
       │  • /user/repos
       │  • /repos/{owner}/{repo}/dependency-graph/sbom
       ▼
┌──────────────┐
│  In-Memory   │
│ Search Index │
│              │
│ Map<pkg,     │
│   [{repo,    │
│     version, │
│     eco}]>   │
└──────────────┘
```

---

## 📁 File Structure

```
centerdeps/
├── index.html           # Main app shell with all views
├── app.js               # Core logic: auth, fetch, index, search
├── style.css            # Premium dark-mode design system
├── oauth-callback.html  # GitHub OAuth redirect handler
├── worker/
│   └── oauth-proxy.js   # Cloudflare Worker for token exchange
├── .gitignore
└── README.md
```

---

## 🔒 Security

| Concern | Mitigation |
|---|---|
| Token exposure | `sessionStorage` only — cleared on tab close |
| Client secret | Stored in Cloudflare Worker env vars, never in frontend |
| CSRF | OAuth `state` parameter validated on callback |
| XSS | All API-returned strings are escaped — no `innerHTML` with raw data |
| Data persistence | Only dependency metadata cached in `localStorage` |
| Scopes | Read-only: `repo` + `read:org` — no write access |

---

## 🧑‍💻 Local Development

```bash
# Start a local server
npx serve .

# Then visit http://localhost:3000
```

For local OAuth to work, temporarily update:
- GitHub OAuth App callback URL → `http://localhost:3000/oauth-callback.html`
- `ALLOWED_ORIGIN` in Cloudflare Worker → `http://localhost:3000`
- `REDIRECT_URI` in `app.js` (auto-derived from `window.location.origin`)

---

## 📄 License

MIT
