# NetScan — Web-Based Nmap Port Scanner

A browser-based network port scanner. Instead of typing `nmap` commands in a
terminal, a user fills out a small form (target + scan type), and the app
runs Nmap on the server and shows the parsed results in the browser.

**⚠️ Only scan systems you own or have explicit written permission to test.**
Scanning networks you don't control can be illegal in many countries even if
no damage is done. `scanme.nmap.org` is a host the Nmap project has
explicitly set up for people to practice on — use that for testing.

---

## 1. How it works (big picture)

```
Browser (form) --POST /scan--> Express server --execFile("nmap", args)--> Nmap
                                     |
                                     v
                          parses Nmap's XML output
                                     |
                                     v
                          sends clean JSON back to browser
                                     |
                                     v
                          browser renders a results table
```

Key files:
- `server.js` — Express app, defines the `/` page and the `/scan` API route.
- `utils/nmapScanner.js` — validates input, runs Nmap, parses XML → JSON.
- `views/index.ejs` — the HTML page (form + results area).
- `public/style.css`, `public/script.js` — styling and frontend logic.
- `Dockerfile` — packages Node.js **and** Nmap together so this can run on
  any hosting platform that supports Docker.

### Why this can't be a "normal" serverless deploy
Platforms like Vercel or Netlify run your code in a sandbox with no shell
access and no system packages — they simply cannot run the real `nmap`
binary. That's why this project ships a `Dockerfile`: it bakes Nmap into
the container image, so any Docker-friendly host (Render, Railway, Fly.io,
a VPS, etc.) can run it.

### Why it's safe from command injection
Two layers of protection in `utils/nmapScanner.js`:
1. **Input validation** — the target must match `/^[a-zA-Z0-9.\-:]{1,255}$/`,
   which blocks characters like `; | & $ \` ( )` that could otherwise be used
   to chain extra shell commands.
2. **No shell involved at all** — we call `execFile("nmap", [...args])`
   instead of `exec("nmap " + target)`. `execFile` passes each argument
   directly to the `nmap` process without ever handing the string to a
   shell to interpret, so even if something slipped past validation, it
   would just be treated as a literal (and probably invalid) target name.
3. **Fixed scan profiles** — users pick from a dropdown (Quick / Standard /
   Full / Ping), and the server maps that choice to a hardcoded flag list.
   The user's raw text never becomes an nmap flag.

---

## 2. Run it locally

### Prerequisites
- Node.js 18+ ([nodejs.org](https://nodejs.org))
- Nmap installed on your machine:
  - **Windows:** download the installer from [nmap.org/download.html](https://nmap.org/download.html)
  - **Mac:** `brew install nmap`
  - **Linux (Debian/Ubuntu):** `sudo apt-get install nmap`

Check it worked:
```bash
nmap --version
```

### Steps
```bash
# 1. Go into the project folder
cd port-scanner

# 2. Install dependencies
npm install

# 3. Start the server
npm start
```

Open `http://localhost:3000` in your browser. Try target `scanme.nmap.org`
with the "Quick Scan" profile first — it's fast and it's a target Nmap's
own team allows scanning.

---

## 3. Deploy it (Render, using Docker)

Render is a good first choice because it has a free/low-cost tier and
native Docker support.

1. Push this project to a GitHub repo.
2. Go to [render.com](https://render.com) → **New +** → **Web Service**.
3. Connect your GitHub repo.
4. Render will detect the `Dockerfile` automatically. If asked for a
   runtime, choose **Docker**.
5. Set:
   - **Instance type:** the free tier works for testing, but full port
     scans (`-p-`) are slow — a paid tier with more CPU will feel snappier.
   - **Port:** Render auto-detects `EXPOSE 3000` from the Dockerfile, but
     you can also add an environment variable `PORT=3000` to be explicit.
6. Click **Create Web Service**. Render will build the Docker image
   (installing Nmap during the build) and deploy it.
7. Once live, you'll get a URL like `https://netscan-xxxx.onrender.com`.

### Alternative hosts
Any Docker-capable host works the same way: **Railway**, **Fly.io**,
**Google Cloud Run**, or your own **VPS** (DigitalOcean/Linode droplet)
running `docker build` + `docker run`.

---

## 4. Important notes before making this public

If you deploy this so anyone on the internet can use it, think about abuse:

- **Rate limiting is already built in** (`express-rate-limit` in
  `server.js`), capping each visitor to 10 scans per 15 minutes. Tune the
  numbers in `server.js` to taste.
- **Consider adding a login step** so only people you trust can trigger
  scans. A public, unauthenticated scanner is an easy way for someone to
  use your server to scan third parties without your knowledge, and your
  server's IP will be the one that shows up in the target's logs.
- **Consider restricting targets** to a specific IP range (e.g. only your
  own home/lab network) instead of allowing any hostname, if you plan to
  share the link with others.
- The "Full Scan" profile (`-p-`, all 65535 ports) can take several
  minutes per target — the 2-minute timeout in `nmapScanner.js` may need
  adjusting, and Render's free tier may time out the HTTP request before
  the scan finishes. For classroom/demo purposes, "Quick" and "Standard"
  are more practical.

---

## 5. Possible next features (good for a hackathon "future work" slide)
- Scan history saved per user (needs a database + login)
- Export results as PDF/CSV
- Scheduled recurring scans with email alerts on new open ports
- Visual network map (nodes/edges) instead of a table
