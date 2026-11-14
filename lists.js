// Источники блок-листов и компактный индекс доменов.
// Индекс = отсортированный Float64Array 53-битных хешей + Uint8Array битовых масок «в каких базах есть».
// ~600 тыс. доменов занимают ~5 МБ и загружаются за миллисекунды, поиск — двоичный.
// Модуль без chrome.* API: тот же код используется для сборки в Node и в расширении.

// Описания источников — в _locales (src_<id>).
// strong: true  — одного этого источника достаточно для красной блокировки
// strong: false — один такой источник даёт жёлтое предупреждение (часто туда попадают взломанные,
//                 а потом очищенные сайты); если он совпал вместе с другим источником — блокировка
export const SOURCES = [
  {
    id: "phishdestroy", bit: 1, name: "PhishDestroy", strong: true, defaultOn: true, format: "lines",
    urls: [
      "https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt",
      "https://cdn.jsdelivr.net/gh/phishdestroy/destroylist@main/rootlist/formats/primary_active/domains.txt",
    ],
  },
  {
    id: "metamask", bit: 2, name: "MetaMask", strong: true, defaultOn: true, format: "metamask",
    urls: [
      "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json",
      "https://cdn.jsdelivr.net/gh/MetaMask/eth-phishing-detect@main/src/config.json",
    ],
  },
  {
    id: "scamsniffer", bit: 4, name: "ScamSniffer", strong: false, defaultOn: true, format: "json-array",
    urls: [
      "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
      "https://cdn.jsdelivr.net/gh/scamsniffer/scam-database@main/blacklist/domains.json",
    ],
  },
  {
    id: "polkadot", bit: 8, name: "Polkadot", strong: true, defaultOn: true, format: "polkadot",
    urls: [
      "https://raw.githubusercontent.com/polkadot-js/phishing/master/all.json",
      "https://cdn.jsdelivr.net/gh/polkadot-js/phishing@master/all.json",
    ],
  },
  {
    id: "phishdb", bit: 32, name: "Phishing.Database", strong: false, defaultOn: false, format: "lines",
    urls: ["https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"],
  },
];

export const STRONG_MASK = SOURCES.filter((s) => s.strong).reduce((m, s) => m | s.bit, 0);
export const DEFAULT_ENABLED = SOURCES.filter((s) => s.defaultOn).reduce((m, s) => m | s.bit, 0);
export const sourceNames = (mask) => SOURCES.filter((s) => mask & s.bit).map((s) => s.name);

// ---------- Хеш cyrb53 (53 бита, безопасно хранится в Float64) ----------
export function hash53(str) {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

// ---------- Разбор форматов ----------
export function normDomain(raw) {
  let d = String(raw || "").trim().toLowerCase();
  if (!d || d[0] === "#" || d[0] === "!") return "";
  d = d.replace(/^\|\|/, "").replace(/\^.*$/, "").replace(/^[a-z]+:\/\//, "");
  d = d.split(/[\/?#\s]/)[0].replace(/:\d+$/, "").replace(/^\*\./, "").replace(/\.$/, "").replace(/^www\./, "");
  if (!d.includes(".") || d.length > 253 || /[^a-z0-9.\-_¡-￿]/.test(d)) return "";
  return d;
}

// возвращает { deny: string[], allow: string[] }
export function parseSource(format, text) {
  const deny = [], allow = [];
  const push = (arr, v) => { const d = normDomain(v); if (d) arr.push(d); };
  if (format === "lines" || format === "urls") {
    for (const line of text.split(/\r?\n/)) push(deny, line);
  } else if (format === "json-array") {
    for (const v of JSON.parse(text)) push(deny, v);
  } else if (format === "metamask") {
    const j = JSON.parse(text);
    for (const v of j.blacklist || []) push(deny, v);
    for (const v of j.whitelist || []) push(allow, v);
  } else if (format === "polkadot") {
    const j = JSON.parse(text);
    for (const v of j.deny || []) push(deny, v);
    for (const v of j.allow || []) push(allow, v);
  }
  return { deny, allow };
}

// ---------- Индекс ----------
export class DomainIndex {
  constructor(hashes = new Float64Array(0), masks = new Uint8Array(0)) {
    this.hashes = hashes;
    this.masks = masks;
  }
  get size() { return this.hashes.length; }

  maskOf(domain) {
    const h = hash53(domain), a = this.hashes;
    let lo = 0, hi = a.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1, v = a[mid];
      if (v === h) return this.masks[mid];
      if (v < h) lo = mid + 1; else hi = mid - 1;
    }
    return 0;
  }

  // сколько доменов у каждого источника
  countBySource() {
    const out = {};
    for (const s of SOURCES) out[s.id] = 0;
    for (const m of this.masks) for (const s of SOURCES) if (m & s.bit) out[s.id]++;
    return out;
  }

  // хеши одного источника (чтобы пересобрать индекс, если источник не обновился)
  hashesOf(bit) {
    const out = [];
    for (let i = 0; i < this.masks.length; i++) if (this.masks[i] & bit) out.push(this.hashes[i]);
    return out;
  }

  // parts: [{ bit, hashes: number[] | Float64Array }]
  static build(parts) {
    const map = new Map();
    for (const { bit, hashes } of parts) for (const h of hashes) map.set(h, (map.get(h) || 0) | bit);
    const hashes = new Float64Array(map.size);
    let i = 0;
    for (const h of map.keys()) hashes[i++] = h;
    hashes.sort();
    const masks = new Uint8Array(hashes.length);
    for (let j = 0; j < hashes.length; j++) masks[j] = map.get(hashes[j]);
    return new DomainIndex(hashes, masks);
  }
}

// ---------- Набор хешей (популярные сайты, белые списки) ----------
export class HashSet {
  constructor(sorted = new Float64Array(0)) { this.a = sorted; }
  static from(domains) {
    const a = Float64Array.from(new Set(domains.map(hash53)));
    a.sort();
    return new HashSet(a);
  }
  has(domain) {
    const h = hash53(domain), a = this.a;
    let lo = 0, hi = a.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1, v = a[mid];
      if (v === h) return true;
      if (v < h) lo = mid + 1; else hi = mid - 1;
    }
    return false;
  }
}
