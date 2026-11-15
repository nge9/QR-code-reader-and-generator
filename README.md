# QR Studio

A local web QR reader and generator.

## Run locally

1. Download this repository using **Code → Download ZIP**, then extract it; or clone it with Git.
2. Open a terminal in the extracted folder.
3. Run `python -m http.server 8000` (or `python3 -m http.server 8000`).
4. Open http://localhost:8000 in your browser.

No npm installation, account, or API key is required. Internet is needed to load the QR and image decoder libraries from jsDelivr. All QR image processing happens in your browser. The app uses system fonts.

## Features

- Read QR codes from uploaded images, drag and drop, or your camera.
- Generate QR codes for links and text, including Arabic and emoji, and download PNG files.
- Record successful reads and generations with timestamps in this browser's local storage.
- Filter, export, and clear activity history.
- Show suspicious links in red, with reasons and confirmation before opening.
- Support browser-decodable images (including common PNG, JPEG, WebP, GIF, SVG, and AVIF), with extra TIFF and HEIC/HEIF decoders.

## Limits

No application can decode every image extension or codec. Uploads are limited to 40 MB. Camera access requires browser permission and localhost or HTTPS. History is specific to the browser and origin; clearing browser storage removes it. URL checks use common warning signs, not a live reputation or malware service, and do not guarantee safety. QR links never open automatically.

## Source

- `index.html`: interface
- `style.css`: responsive styling
- `app.js`: QR reader, generator, history, and URL checks

Libraries loaded from CDN: jsQR, qrcode-generator, UTIF, pako, and heic2any. Their respective licenses apply.

## Verification

QR generation/decoding round trips passed for ASCII URLs, Arabic text, and emoji. URL warning cases passed. Visual layout and camera testing remain unverified.
