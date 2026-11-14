import { t, applyI18n, uiLang } from "./i18n.js";

applyI18n();
const $ = (id) => document.getElementById(id);
const fmtDate = (ts) =>
  ts ? new Date(ts).toLocaleString(uiLang(), { day: "numeric", month: "long", hour: "2-digit", minute: "2-digit" }) : "—";
const fmtNum = (n) => (n || 0).toLocaleString(uiLang());
const SOURCE_BITS = { phishdestroy: 1, metamask: 2, scamsniffer: 4, polkadot: 8, phishdb: 32 };

let pollTimer = null;

async function render() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let url = tab?.url || "";
  if (url.startsWith(chrome.runtime.getURL("blocked.html"))) {
    url = new URL(url).searchParams.get("url") || "";
  }
  const st = await chrome.runtime.sendMessage({ type: "status", url });

  // текущий сайт
  const dot = $("dot");
  dot.className = "dot";
  $("siteHost").textContent = st.host || "—";
  $("untrustBtn").hidden = true;
  const v = st.verdict;
  if (!st.host) {
    $("siteStatus").textContent = t("notChecked");
  } else if (v?.kind === "list") {
    dot.classList.add("bad");
    $("siteStatus").textContent = t("statusList", v.sourceNames?.join(", ") || "");
  } else if (v?.kind === "listweak") {
    dot.classList.add("warn");
    $("siteStatus").textContent = t("statusWeak", v.sourceNames?.join(", ") || "");
  } else if (v?.kind === "lookalike") {
    dot.classList.add("warn");
    $("siteStatus").textContent = t("statusLook", v.brand || t("genericCrypto"));
  } else if (st.allowedNow) {
    dot.classList.add("warn");
    $("siteStatus").textContent = t("statusAllowed");
    $("untrustBtn").hidden = false;
    $("untrustBtn").onclick = async () => {
      await chrome.runtime.sendMessage({ type: "untrust", host: st.host });
      render();
    };
  } else {
    dot.classList.add("ok");
    $("siteStatus").textContent = t("statusOk");
  }

  // статистика
  $("count").textContent = fmtNum(st.total);
  $("blocked").textContent = fmtNum(st.stats?.blocked);
  $("warned").textContent = fmtNum(st.stats?.warned);
  const enabledSrc = st.sources.filter((x) => x.enabled);
  const allFailed = enabledSrc.length && enabledSrc.every((x) => x.error);
  $("updated").textContent = st.refreshing
    ? t("updating")
    : allFailed
      ? t("offline")
      : st.refreshedAt
        ? t("updatedAt", fmtDate(st.refreshedAt))
        : t("bundledCopy");

  // источники
  const ul = $("sources");
  ul.textContent = "";
  for (const src of st.sources) {
    const li = document.createElement("li");
    const label = document.createElement("label");
    const info = document.createElement("div");
    const name = document.createElement("div");
    name.className = "src-name";
    name.textContent = src.name;
    if (!src.strong) {
      const tag = document.createElement("span");
      tag.className = "tag";
      tag.textContent = t("warnTag");
      tag.title = t("warnTagTitle");
      name.append(tag);
    }
    const sub = document.createElement("div");
    sub.className = "sub";
    const about = t("src_" + src.id);
    sub.textContent = src.enabled && src.count ? `${fmtNum(src.count)} · ${about}` : about;
    if (src.error) {
      const err = document.createElement("div");
      err.className = "err";
      err.textContent = t("lastUpdateFailed");
      sub.append(err);
    }
    info.append(name, sub);
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = src.enabled;
    cb.addEventListener("change", async () => {
      const bit = SOURCE_BITS[src.id];
      const enabled = cb.checked ? st.settings.enabled | bit : st.settings.enabled & ~bit;
      await chrome.runtime.sendMessage({ type: "settings", settings: { enabled } });
      render();
    });
    label.append(info, cb);
    li.append(label);
    ul.append(li);
  }

  $("lookalike").checked = st.settings.lookalike !== false;

  // доверенные
  const list = $("trustedList");
  list.textContent = "";
  $("trustedBox").hidden = !st.trusted.length;
  for (const h of st.trusted) {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.textContent = h;
    const del = document.createElement("button");
    del.textContent = t("remove");
    del.onclick = async () => {
      await chrome.runtime.sendMessage({ type: "untrust", host: h });
      render();
    };
    li.append(span, del);
    list.append(li);
  }

  // пока идёт обновление — перерисовываем
  clearTimeout(pollTimer);
  if (st.refreshing) pollTimer = setTimeout(render, 1500);
}

$("refresh").addEventListener("click", async () => {
  const b = $("refresh");
  b.disabled = true;
  b.textContent = t("refreshing");
  setTimeout(render, 300);
  const r = await chrome.runtime.sendMessage({ type: "refresh" });
  b.textContent = r?.ok ? t("done") : t("partial");
  setTimeout(() => { b.textContent = t("refresh"); b.disabled = false; }, 1500);
  render();
});

$("lookalike").addEventListener("change", async (e) => {
  await chrome.runtime.sendMessage({ type: "settings", settings: { lookalike: e.target.checked } });
  render();
});

render();
