import { DEFAULT_API, getConfig } from "./common.js";

const apiBase = document.getElementById("apiBase");
const apiKey = document.getElementById("apiKey");
const status = document.getElementById("status");

const config = await getConfig();
apiBase.value = config.apiBase;
apiKey.value = config.apiKey;

document.getElementById("save").addEventListener("click", async () => {
  const value = (apiBase.value.trim() || DEFAULT_API).replace(/\/+$/, "");
  let url;
  try {
    url = new URL(value);
  } catch {
    status.textContent = "That is not a valid address.";
    return;
  }
  const local = ["localhost", "127.0.0.1"].includes(url.hostname);
  if (!local && url.protocol !== "https:") {
    status.textContent = "A non-local server must use https.";
    return;
  }
  if (!local) {
    const granted = await chrome.permissions.request({ origins: [`${url.origin}/*`] });
    if (!granted) {
      status.textContent = "Permission was not granted; settings not saved.";
      return;
    }
  }
  await chrome.storage.sync.set({ apiBase: url.origin, apiKey: apiKey.value.trim() });
  status.textContent = "Saved.";
});
