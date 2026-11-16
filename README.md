# QR Studio

A local QR reader and generator with VirusTotal URL reports.

## Run locally with VirusTotal

1. Download **Code → Download ZIP**, extract it, and open a terminal in the folder.
2. Get your personal API key from https://www.virustotal.com/gui/my-apikey (a VirusTotal account is required).
3. Set the key in your terminal, then start the local server:

**macOS / Linux**

```bash
read -rsp "VirusTotal API key: " VT_API_KEY
export VT_API_KEY
printf '\n'
python3 server.py
```

**Windows PowerShell**

```powershell
$env:VT_API_KEY = Read-Host "VirusTotal API key"
python server.py
```

4. Open **http://localhost:8000**.

Python 3.9+ is required. No pip or npm installation is needed. Do not use `python -m http.server` for VirusTotal: it cannot run the API endpoint. The app can still read and generate QR codes without a key, but reports will be unavailable and links will remain unverified.

Keep your key private. Do not put it in JavaScript, screenshots, commits, or GitHub. The backend reads `VT_API_KEY` from its environment and sends it only to VirusTotal. `.env.example` is documentation; `.env` files are not automatically loaded.

## How link checking works

- With **Check web links with VirusTotal** enabled, reading or viewing a web URL requests VirusTotal's existing report. Generated web links are checked too.
- The full URL is shared with VirusTotal. Turn checking off before reading private links, login tokens, password-reset URLs, or other sensitive content.
- Malicious or suspicious detections turn the URL red, show engine counts, and require confirmation before opening. Local warning signs also keep URLs red.
- No report, unavailable API, quota errors, incomplete results, and clean reports older than seven days remain **unverified**. Opening an unverified link requires confirmation.
- **No detections is not a safety guarantee.** VirusTotal can miss new threats, and results describe a past analysis. The last analysis date is displayed.
- **Submit for a new scan** is a separate action with confirmation. Submitted URLs may be shared with VirusTotal's security community. After submission, wait at least a minute, then click **Check report again**; queued does not mean safe.
- Links cannot be opened from the result while its check is in progress. Links never open automatically.
- VirusTotal limits depend on your account. The server permits at most four upstream requests per minute and reports quota errors without retry loops.

The server binds only to your computer's loopback interface, serves a small asset allowlist, checks request origins, and never fetches the decoded destination itself. It does not log QR URLs or expose the API key to the browser. This local server is not intended for public hosting or GitHub Pages.

## Other features

- Image upload, drag and drop, and camera scanning.
- QR generation for URLs, text, Arabic, and emoji; PNG download.
- Timestamped browser-local history with VirusTotal results, filtering, JSON export, and clearing.
- Browser-supported images plus TIFF and HEIC/HEIF decoders. Universal format support is not possible; images are limited to 40 MB.

QR images are processed in your browser. Internet is needed for CDN libraries and VirusTotal reports. Camera access needs browser permission and localhost or HTTPS. Clearing browser storage removes history.

## Files and tests

- `index.html`, `style.css`, `app.js`: browser app.
- `server.py`: standard-library local server and VirusTotal API integration.
- `test_server.py`: offline regression tests using mocked VirusTotal responses.

```bash
python -m unittest -v test_server.py
```

Libraries: jsQR, qrcode-generator, UTIF, pako, and heic2any, under their respective licenses.
