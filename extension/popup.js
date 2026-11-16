import { scan, VERDICTS } from "./common.js";

const input = document.getElementById("input");
const box = document.getElementById("result");

function el(tag, props = {}, children = []) {
  const node = Object.assign(document.createElement(tag), props);
  children.forEach((child) => node.append(child));
  return node;
}

// Everything is rendered with textContent: scanned content is never inserted as HTML.
function show(entry) {
  box.hidden = false;
  box.replaceChildren();
  box.append(el("p", { className: "muted", textContent: entry.value.slice(0, 140) }));
  if (entry.error) {
    box.append(el("p", { textContent: `Could not check this: ${entry.error}` }));
    return;
  }
  const { result } = entry;
  const meta = VERDICTS[result.verdict];
  const dot = el("span", { className: "dot", textContent: meta.icon });
  dot.style.background = meta.color;
  box.append(
    el("div", { className: "verdict" }, [
      dot,
      el("span", { textContent: meta.label }),
      el("span", { className: "score", textContent: `${result.risk_score}/100` }),
    ]),
    el("ul", {}, result.reasons.map((reason) => el("li", { textContent: reason }))),
  );
}

document.getElementById("check").addEventListener("click", async () => {
  const value = input.value.trim();
  if (!value) return;
  const kind = /^\S+\.\S+$/.test(value) ? "url" : "text";
  try {
    show({ value, result: await scan(kind, value) });
  } catch (error) {
    show({ value, error: String(error.message || error) });
  }
});

const { last } = await chrome.storage.session.get("last");
if (last) show(last);
chrome.action.setBadgeText({ text: "" });
