import { scan, VERDICTS } from "./common.js";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "jasusi-link", title: "Check this link with JASUSI", contexts: ["link"] });
  chrome.contextMenus.create({ id: "jasusi-text", title: "Check selected text with JASUSI", contexts: ["selection"] });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  const kind = info.menuItemId === "jasusi-link" ? "url" : "text";
  const value = kind === "url" ? info.linkUrl : info.selectionText;
  if (!value) return;
  await chrome.action.setBadgeBackgroundColor({ color: "#52514e" });
  await chrome.action.setBadgeText({ text: "…" });
  let last;
  try {
    const result = await scan(kind, value);
    last = { kind, value, result, at: Date.now() };
    const meta = VERDICTS[result.verdict];
    await chrome.action.setBadgeBackgroundColor({ color: meta.color });
    await chrome.action.setBadgeText({ text: meta.badge });
  } catch (error) {
    last = { kind, value, error: String(error.message || error), at: Date.now() };
    await chrome.action.setBadgeBackgroundColor({ color: "#52514e" });
    await chrome.action.setBadgeText({ text: "x" });
  }
  // Kept for this browser session only, so the popup can show it. Cleared when the browser closes.
  await chrome.storage.session.set({ last });
  // Opening the popup needs a recent user gesture; if the browser refuses, the badge still shows the verdict.
  try { await chrome.action.openPopup(); } catch { /* user can click the icon */ }
});
