import { check, normalizeHost } from "./detect.js";
import { SOURCES, DEFAULT_ENABLED, parseSource, hash53, DomainIndex, HashSet, sourceNames } from "./lists.js";

const REFRESH_MINUTES = 720; // каждые 12 часов
const MIN_KEEP_RATIO = 0.3;  // если источник внезапно «похудел» больше чем на 70% — считаем ответ битым

let state = null;
let loading = null;
let refreshing = null;

// ---------- IndexedDB (бинарный индекс не помещается в chrome.storage эффективно) ----------
function db() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open("antidrainer", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("kv");
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function idbGet(key) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const r = d.transaction("kv").objectStore("kv").get(key);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function idbSet(key, value) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const tx = d.transaction("kv", "readwrite");
    tx.objectStore("kv").put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

const indexFromBuffer = (buf) => {
  const n = new DataView(buf).getUint32(0, true);
  return new DomainIndex(new Float64Array(buf, 8, n), new Uint8Array(buf, 8 + n * 8, n));
};
const indexToBuffer = (ix) => {
  const n = ix.size, buf = new ArrayBuffer(8 + n * 8 + n);
  new DataView(buf).setUint32(0, n, true);
  new Float64Array(buf, 8, n).set(ix.hashes);
  new Uint8Array(buf, 8 + n * 8, n).set(ix.masks);
  return buf;
};
const bundled = (path) => fetch(chrome.runtime.getURL(path));

// ---------- Загрузка состояния ----------
async function load() {
  let indexBuf = await idbGet("index");
  let allowBySource = await idbGet("allowBySource");
  let meta = await idbGet("meta");
  if (!indexBuf) {
    // первый запуск: встроенная копия баз
    indexBuf = await (await bundled("data/index.bin")).arrayBuffer();
    allowBySource = await (await bundled("data/allow.json")).json();
    meta = await (await bundled("data/meta.json")).json();
    meta.bundled = true;
    await idbSet("index", indexBuf);
    await idbSet("allowBySource", allowBySource);
    await idbSet("meta", meta);
  }
  const popular = new HashSet(new Float64Array(await (await bundled("data/popular.bin")).arrayBuffer()));
  const midpop = HashSet.from(await (await bundled("data/midpop.json")).json());

  const local = await chrome.storage.local.get(["userAllow", "settings"]);
  const session = await chrome.storage.session.get(["sessionAllow"]);
  const index = indexFromBuffer(indexBuf);

  state = {
    index,
    popular,
    midpop,
    allowBySource: allowBySource || {},
    allow: HashSet.from(Object.values(allowBySource || {}).flat()),
    meta: meta || { sources: {} },
    counts: index.countBySource(),
    userAllow: new Set(local.userAllow || []),
    sessionAllow: new Set(session.sessionAllow || []),
    settings: { lookalike: true, enabled: DEFAULT_ENABLED, ...(local.settings || {}) },
  };
  return state;
}

function ready() {
  if (state) return Promise.resolve(state);
  if (!loading) loading = load().finally(() => (loading = null));
  return loading;
}

const listsFor = (s) => ({
  index: s.index, enabled: s.settings.enabled, popular: s.popular, midpop: s.midpop, allow: s.allow,
  userAllow: s.userAllow, sessionAllow: s.sessionAllow,
});

// ---------- Обновление баз ----------
async function fetchSource(src, etag) {
  let lastErr = "no response";
  for (const url of src.urls) {
    try {
      const headers = etag && url === src.urls[0] ? { "If-None-Match": etag } : {};
      const r = await fetch(url, { cache: "no-store", headers });
      if (r.status === 304) return { notModified: true };
      if (!r.ok) { lastErr = `HTTP ${r.status}`; continue; }
      const text = await r.text();
      return { text, etag: url === src.urls[0] ? r.headers.get("etag") : null };
    } catch (e) {
      lastErr = String(e?.message || e);
    }
  }
  return { error: lastErr };
}

async function refreshAll() {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    const s = await ready();
    const etags = (await idbGet("etags")) || {};
    const meta = { ...s.meta, sources: { ...(s.meta.sources || {}) }, bundled: false };
    const parts = [];
    const allowBySource = { ...s.allowBySource };
    const results = {};

    for (const src of SOURCES) {
      const enabled = (s.settings.enabled & src.bit) !== 0;
      const prev = s.index.hashesOf(src.bit);
      if (!enabled) { parts.push({ bit: src.bit, hashes: prev }); continue; } // выключенные не качаем

      const res = await fetchSource(src, prev.length ? etags[src.id] : null);
      const m = (meta.sources[src.id] = { ...(meta.sources[src.id] || {}), checkedAt: Date.now() });
      if (res.notModified) {
        parts.push({ bit: src.bit, hashes: prev });
        m.error = null;
        results[src.id] = "unchanged";
        continue;
      }
      if (res.error) {
        parts.push({ bit: src.bit, hashes: prev });
        m.error = res.error;
        results[src.id] = "error: " + res.error;
        continue;
      }
      let parsed;
      try { parsed = parseSource(src.format, res.text); } catch (e) {
        parts.push({ bit: src.bit, hashes: prev });
        m.error = "parse error";
        results[src.id] = m.error;
        continue;
      }
      const hashes = [...new Set(parsed.deny.map(hash53))];
      if (prev.length > 1000 && hashes.length < prev.length * MIN_KEEP_RATIO) {
        parts.push({ bit: src.bit, hashes: prev });
        m.error = `too few entries (${hashes.length})`;
        results[src.id] = m.error;
        continue;
      }
      parts.push({ bit: src.bit, hashes });
      allowBySource[src.id] = [...new Set(parsed.allow)];
      if (res.etag) etags[src.id] = res.etag;
      Object.assign(m, { updatedAt: Date.now(), error: null, count: hashes.length });
      results[src.id] = "updated";
    }

    const index = DomainIndex.build(parts);
    await idbSet("index", indexToBuffer(index));
    await idbSet("allowBySource", allowBySource);
    await idbSet("etags", etags);
    meta.refreshedAt = Date.now();
    await idbSet("meta", meta);

    Object.assign(s, {
      index, allowBySource, meta,
      allow: HashSet.from(Object.values(allowBySource).flat()),
      counts: index.countBySource(),
    });
    return { ok: Object.values(results).every((r) => !r.startsWith("error")), results, total: index.size };
  })().finally(() => (refreshing = null));
  return refreshing;
}

chrome.runtime.onInstalled.addListener(async () => {
  chrome.alarms.create("refresh", { periodInMinutes: REFRESH_MINUTES, delayInMinutes: 1 });
  await ready();
  refreshAll();
});
chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.get("refresh", (a) => {
    if (!a) chrome.alarms.create("refresh", { periodInMinutes: REFRESH_MINUTES, delayInMinutes: 1 });
  });
});
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "refresh") refreshAll();
});

// ---------- Проверка переходов ----------
const recent = new Map();

async function handle(tabId, url, frameId, lifecycle) {
  if (tabId < 0 || frameId !== 0 || lifecycle === "prerender") return;
  let u;
  try { u = new URL(url); } catch { return; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return;

  const s = await ready();
  const verdict = check(u.hostname, listsFor(s), s.settings);
  if (!verdict) return;

  const prev = recent.get(tabId);
  if (prev && prev.url === url && Date.now() - prev.t < 3000) return;
  recent.set(tabId, { url, t: Date.now() });

  const p = new URLSearchParams({
    url,
    kind: verdict.kind,
    host: normalizeHost(u.hostname),
    brand: verdict.brand || "",
    official: verdict.official || "",
    matched: verdict.matched || "",
    sources: verdict.sources ? sourceNames(verdict.sources).join(", ") : "",
    homoglyph: verdict.homoglyph ? "1" : "",
  });
  chrome.tabs.update(tabId, { url: chrome.runtime.getURL("blocked.html") + "?" + p.toString() });

  const { stats = { blocked: 0, warned: 0 } } = await chrome.storage.local.get("stats");
  if (verdict.kind === "list") stats.blocked++;
  else stats.warned++;
  chrome.storage.local.set({ stats });
}

chrome.webNavigation.onBeforeNavigate.addListener((d) => handle(d.tabId, d.url, d.frameId, d.documentLifecycle));
chrome.webNavigation.onCommitted.addListener((d) => handle(d.tabId, d.url, d.frameId, d.documentLifecycle));
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.url) handle(tabId, info.url, 0);
});
chrome.tabs.onRemoved.addListener((tabId) => recent.delete(tabId));

// ---------- Сообщения ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const s = await ready();
    switch (msg.type) {
      case "allow": {
        const host = normalizeHost(msg.host);
        if (!host) return sendResponse({ ok: false });
        s.sessionAllow.add(host);
        await chrome.storage.session.set({ sessionAllow: [...s.sessionAllow] });
        if (msg.permanent) {
          s.userAllow.add(host);
          await chrome.storage.local.set({ userAllow: [...s.userAllow] });
        }
        return sendResponse({ ok: true });
      }
      case "status": {
        let verdict = null, host = "";
        try {
          const u = new URL(msg.url);
          if (u.protocol === "http:" || u.protocol === "https:") {
            host = normalizeHost(u.hostname);
            verdict = check(u.hostname, listsFor(s), s.settings);
            if (verdict?.sources) verdict.sourceNames = sourceNames(verdict.sources);
          }
        } catch {}
        const { stats } = await chrome.storage.local.get("stats");
        return sendResponse({
          host, verdict, stats,
          settings: s.settings,
          trusted: [...s.userAllow],
          allowedNow: !!host && (s.sessionAllow.has(host) || s.userAllow.has(host)),
          total: s.index.size,
          refreshing: !!refreshing,
          refreshedAt: s.meta.refreshedAt || null,
          bundled: !!s.meta.bundled,
          sources: SOURCES.map((src) => ({
            id: src.id, name: src.name, strong: src.strong,
            enabled: (s.settings.enabled & src.bit) !== 0,
            count: s.counts[src.id] || 0,
            updatedAt: s.meta.sources?.[src.id]?.updatedAt || null,
            error: s.meta.sources?.[src.id]?.error || null,
          })),
        });
      }
      case "refresh":
        return sendResponse(await refreshAll());
      case "settings": {
        const before = s.settings.enabled;
        s.settings = { ...s.settings, ...msg.settings };
        await chrome.storage.local.set({ settings: s.settings });
        // включили источник, которого ещё нет в базе — скачиваем
        const added = SOURCES.some((src) => !(before & src.bit) && (s.settings.enabled & src.bit) && !s.counts[src.id]);
        if (added) refreshAll();
        return sendResponse({ ok: true, downloading: added });
      }
      case "untrust": {
        s.userAllow.delete(msg.host);
        s.sessionAllow.delete(msg.host);
        await chrome.storage.local.set({ userAllow: [...s.userAllow] });
        await chrome.storage.session.set({ sessionAllow: [...s.sessionAllow] });
        return sendResponse({ ok: true });
      }
      default:
        sendResponse({ ok: false });
    }
  })();
  return true;
});

// Миграция с версии 1.0: старая база в chrome.storage больше не нужна
chrome.storage.local.remove(["listText", "listCount", "listUpdatedAt", "listSource", "lastError", "lastErrorAt"]);
