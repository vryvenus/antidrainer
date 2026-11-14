import { t, applyI18n } from "./i18n.js";

// Все значения из адреса выводятся только через textContent — никакого innerHTML.
const q = new URLSearchParams(location.search);
const url = q.get("url") || "";
const kind = ["list", "listweak"].includes(q.get("kind")) ? q.get("kind") : "lookalike";
const host = q.get("host") || "";
const brand = q.get("brand") || "";
const official = /^[a-z0-9.-]+$/i.test(q.get("official") || "") ? q.get("official") : "";
const matched = q.get("matched") || "";
const homoglyph = q.get("homoglyph") === "1";
const sources = (q.get("sources") || "").replace(/[^\w .,\-]/g, "");

applyI18n();
const $ = (id) => document.getElementById(id);

// текст с выделенным фрагментом: шаблон с {1} -> <strong>
function rich(el, template, value) {
  el.textContent = "";
  const [before, after = ""] = template.split("\u0000");
  el.append(before);
  const b = document.createElement("strong");
  b.textContent = value;
  el.append(b, after);
}
const withBold = (key, value, ...rest) => t(key, "\u0000", ...rest);

$("host").textContent = host;

if (kind === "list") {
  document.title = t("pageTitleList");
  $("badge").textContent = t("badgeList");
  $("title").textContent = t("titleList");
  const lead = $("lead");
  lead.textContent = "";
  if (sources) {
    lead.append(t("leadList") + " ");
    const b = document.createElement("strong");
    b.textContent = sources;
    lead.append(b, ". ");
  } else {
    lead.append(t("leadListNoSrc") + " ");
  }
  if (matched && matched !== host) lead.append(t("matchedOn", matched) + " ");
  lead.append(t("leadListTail"));
  $("confirmText").textContent = t("confirmList");
} else if (kind === "listweak") {
  document.body.classList.add("warn");
  document.title = t("pageTitleWeak");
  $("badge").textContent = t("badgeWeak");
  $("title").textContent = t("titleWeak");
  rich($("lead"), withBold("leadWeak"), sources || "—");
  $("confirmText").textContent = t("confirmWeak");
  $("trust").hidden = false;
} else {
  document.body.classList.add("warn");
  document.title = t("pageTitleLook");
  $("badge").textContent = t("badgeLook");
  $("title").textContent = brand ? t("titleLookBrand", brand) : t("titleLook");
  rich($("lead"), withBold("leadLook"), brand || t("genericCryptoName"));
  $("confirmText").textContent = t("confirmLook");
  $("trust").hidden = false;
}

if (brand && official) {
  const line = $("brandLine");
  line.hidden = false;
  line.textContent = "";
  const parts = t("brandLine", "\u0001", "\u0002").split(/(\u0001|\u0002)/);
  for (const p of parts) {
    if (p === "\u0001" || p === "\u0002") {
      const b = document.createElement("strong");
      b.textContent = p === "\u0001" ? brand : official;
      line.append(b);
    } else line.append(p);
  }
  const a = $("goOfficial");
  a.hidden = false;
  a.href = "https://" + official + "/";
  a.textContent = t("goOfficial", official);
}
if (homoglyph) $("homoglyphLine").hidden = false;

$("leave").addEventListener("click", async () => {
  try {
    const tab = await chrome.tabs.getCurrent();
    if (tab) return chrome.tabs.remove(tab.id);
  } catch {}
  window.close();
  location.replace("about:blank");
});

const confirmBox = $("confirm");
confirmBox.addEventListener("change", () => {
  $("proceed").disabled = !confirmBox.checked;
  $("trust").disabled = !confirmBox.checked;
});

async function allowAndGo(permanent) {
  let target;
  try {
    target = new URL(url);
    if (target.protocol !== "http:" && target.protocol !== "https:") return;
  } catch { return; }
  const allowHost = target.hostname.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
  const r = await chrome.runtime.sendMessage({ type: "allow", host: allowHost, permanent });
  if (r && r.ok) location.replace(target.href);
}
$("proceed").addEventListener("click", () => allowAndGo(false));
$("trust").addEventListener("click", () => allowAndGo(true));
