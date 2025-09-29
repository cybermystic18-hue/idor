# OpenProfiles — IDOR CTF challenge (Render-ready)

This repo is a small, realistic IDOR (Insecure Direct Object Reference) challenge intended for CTF use.
It's ready to push to GitHub and deploy on Render (or any Node-capable hosting).

## What it contains
- `server.js` — Express app serving static frontend and API.
- `web/` — optional static frontend to make the site realistic.
- `data/users.json` — user records (admin is id 1 and contains the flag).

## Flag
`ICTAK{idor_real_and_ripe}`

## Quick local run
```bash
npm install
npm start
# visit http://localhost:3000
```

## Deploy to Render (recommended)
1. Push this repo to GitHub.
2. On Render.com create a new **Web Service**.
   - Connect your GitHub repository.
   - Build command: (leave empty) — Render will run `npm install`.
   - Start command: `npm start`
   - Branch: select your repo branch (e.g., `main`).
3. Deploy — Render will give you a public URL like `https://your-service.onrender.com`.
4. Test endpoints:
   - `GET /api/me`
   - `GET /api/users`
   - `GET /api/profile/1` -> contains the flag

## Notes / customization
- You can add more realistic fields to `data/users.json`.
- Optionally replace file-backed storage with SQLite for more realism.
- Add rate-limiting, logging or telemetry if desired (not necessary for CTF).

## License & safety
Educational use only. Do not deploy these vulnerabilities on production systems.
