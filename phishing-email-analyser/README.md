# Phishing Email Analyser

A free, private phishing and social-engineering analyser that runs **entirely in your web browser**.
Paste a suspicious email or a phone-call transcript and get a risk score, a clear explanation, an attack-path simulation mapped to MITRE ATT&CK, incident-response guidance and IOCs. It also includes an awareness challenge, personalised training and a team dashboard.

No server, no database, no accounts, no AI APIs, no tracking.

---

## Run it on your computer (30 seconds)

1. Unzip the folder.
2. Double-click `index.html`. It opens in your browser and works offline.

## Put it on the internet for free

All three options are free for static sites like this one.

**Option A: Netlify Drop (easiest, no account needed to try)**
1. Go to <https://app.netlify.com/drop>.
2. Drag the whole `phishing-email-analyser` folder onto the page.
3. You get a public link straight away. Create a free account to keep it permanently.

**Option B: GitHub Pages (good for your portfolio)**
1. Create a free GitHub account and a new **public** repository, e.g. `phishing-email-analyser`.
2. Click **Add file → Upload files**, drag in everything from this folder (keep the `css` and `js` folders), then **Commit**.
3. Go to **Settings → Pages**, set *Source* to **Deploy from a branch**, choose `main` and `/ (root)`, then **Save**.
4. After a minute your site is live at `https://YOUR-USERNAME.github.io/phishing-email-analyser/`.

**Option C: Cloudflare Pages**: create a project, choose *Direct Upload*, and upload the folder.

> Optional hardening for hosts that support headers (Netlify, Cloudflare): the included `_headers` file adds the same privacy policy as an HTTP header, plus `frame-ancestors 'none'` so other sites cannot embed yours.

---

## What is in the folder

| File | What it does (plain English) |
|---|---|
| `index.html` | The page layout: tabs, text box and buttons. Contains the privacy lock (see below). |
| `css/styles.css` | Colours, spacing and layout, including dark mode and phone layout. |
| `js/rules.js` | The **knowledge base**: every warning sign, its weight and its explanation. Edit this to add your own rules. |
| `js/analyser.js` | The **detection engine**: reads the text, checks links, attachments and headers, calculates the score and extracts IOCs. |
| `js/guidance.js` | Turns findings into "what happens if…", the attack path and incident-response steps. |
| `js/content.js` | Example emails, the 12 challenge messages and the training lessons. |
| `js/core.js` | Shared helpers: safe storage, safe display of text, awareness-score formula. |
| `js/app.js` | Connects the Analyse page buttons to the engine and draws the report. |
| `js/learn.js` | The Challenge and Training pages. |
| `js/dashboard.js` | Personal and team dashboards. |
| `tests/run-tests.js` | 70 automated checks for the detection engine (`node tests/run-tests.js`). |
| `tools/build-preview.py` | Makes a single-file copy (`dist/preview.html`) for previews. Not needed for hosting. |

---

## Key decisions, explained

**Why plain HTML, CSS and JavaScript?** Browsers understand these three languages natively. There is nothing to install or build and nothing to break when a framework updates. It is also the easiest code to learn from.

**How is privacy guaranteed?** The page has a *Content Security Policy* (CSP), a line in `index.html` that the browser enforces. `connect-src 'none'` means the page is forbidden from sending data to any server. Even if someone added a bad line of code, the browser would block the upload. Try it: open DevTools (F12) → **Network**, click Analyse, and you'll see no new requests.

**Why no Google Fonts?** Loading a font from Google tells Google that someone visited. The app uses fonts already on your device.

**Why no automatic voice transcription?** The speech recognition built into browsers (Web Speech API) sends audio to Google or Apple servers. That would break the privacy rule, so you load a recording to *play locally* and type what was said.

**How are emails displayed safely?** Email text is untrusted. If we inserted it into the page as HTML, a malicious email could run code (an attack called **XSS, Cross-Site Scripting**). The app only ever inserts text as plain characters (`textContent`), so `<script>` in an email is just shown, never run. Links are read as text and **never visited**.

**What is stored?** Only small summaries (score and warning-sign names, never the message), challenge answers and training progress, in your browser's `localStorage`. "Privacy & how it works → Delete all data" wipes it.

**How does the team dashboard work without a database?** Each person exports a small JSON file of scores. A manager imports those files, and the combining happens in the manager's browser.

**How is the risk score calculated?** Each warning sign has a weight (a password request = 25, a generic greeting = 6). Dangerous combinations add a bonus. The total is squashed onto 0–100 with `100 × (1 − e^(−total/55))`, so it rises quickly at first and never exceeds 100. Bands: Low 0–19, Medium 20–44, High 45–69, Critical 70–100.

---

## Ideas to extend it (great practice)

1. **Add a rule.** Open `js/rules.js`, copy an existing rule, change the `id`, `title`, `patterns` and `explain`. Re-run the tests.
2. **Add a brand.** Add it to `BRANDS` in `rules.js` with its real domains so look-alikes get caught.
3. **Add challenge messages.** Add entries to `CHALLENGE` in `js/content.js`.
4. **Parse `.eml` files.** Let users drop an exported email file onto the page (use `FileReader`, like the dashboard import).
5. **QR-code phishing ("quishing").** Decode QR images locally with a small library and analyse the URL.

## Limits

This is a rule-based teaching tool. It can miss carefully written attacks and can flag genuine messages. A low score does not prove a message is safe. Always verify through a trusted channel and report suspicious messages to your security team.
