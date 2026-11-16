# JASUSI Chrome extension (Manifest V3)

Right-click a **link** or **selected text** → *Check with JASUSI*. The verdict appears on the toolbar
icon and in the popup. You can also paste text into the popup.

## Load it
1. Start the API (`uvicorn app.main:app --app-dir backend`), which listens on `http://localhost:8000`.
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked** and pick this folder.
3. Optional: open the extension's **Settings** to point it at another server or add an API key.

## Privacy and safety
- A checked link is sent to your JASUSI server as text. Neither the extension nor the server opens it.
- No browsing history is read; the extension only sees what you explicitly right-click or paste.
- The last result is kept for the browser session only.
