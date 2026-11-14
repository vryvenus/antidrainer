import { STRONG_MASK } from "./lists.js";

// Чистая логика проверки доменов: без chrome.* API, чтобы её можно было тестировать в Node.

// ---------- Бренды, которые чаще всего подделывают ----------
// mode "contains": слово ищется внутри адреса (с учётом букв-двойников и опечаток)
// mode "token":    короткие названия — срабатывают только как отдельное слово (okx-wallet.com)
export const BRANDS = [
  { name: "TRONSCAN", key: "tronscan", official: ["tronscan.org", "tronscan.io"] },
  { name: "TronLink", key: "tronlink", official: ["tronlink.org"] },
  { name: "JustLend", key: "justlend", official: ["justlend.org"] },
  { name: "MetaMask", key: "metamask", official: ["metamask.io"] },
  { name: "Trust Wallet", key: "trustwallet", official: ["trustwallet.com"] },
  { name: "Binance", key: "binance", official: ["binance.com", "binance.us", "binance.org", "binance.vision", "binance.bh", "binance.th", "binance.tr", "binanceblockchainweek.com"] },
  { name: "Coinbase", key: "coinbase", official: ["coinbase.com", "coinbase-corp.com"] },
  { name: "Bybit", key: "bybit", mode: "token", official: ["bybit.com", "bybit.eu"] },
  { name: "KuCoin", key: "kucoin", mode: "token", official: ["kucoin.com"] },
  { name: "WhiteBIT", key: "whitebit", official: ["whitebit.com"] },
  { name: "Uniswap", key: "uniswap", official: ["uniswap.org"] },
  { name: "PancakeSwap", key: "pancakeswap", official: ["pancakeswap.finance"] },
  { name: "Ledger Live", key: "ledgerlive", official: ["ledger.com"] },
  { name: "Trezor", key: "trezor", mode: "token", needContext: true, official: ["trezor.io"] },
  { name: "Etherscan", key: "etherscan", official: ["etherscan.io"] },
  { name: "BscScan", key: "bscscan", official: ["bscscan.com"] },
  { name: "Solscan", key: "solscan", official: ["solscan.io"] },
  { name: "monobank", key: "monobank", official: ["monobank.ua"] },
  { name: "Privat24", key: "privat24", noTypo: true, official: ["privat24.ua", "privatbank.ua"] },
  { name: "PrivatBank", key: "privatbank", mode: "token", needContext: true, official: ["privatbank.ua", "privat24.ua"] },
  { name: "OKX", key: "okx", mode: "token", official: ["okx.com"] },
  { name: "MEXC", key: "mexc", mode: "token", official: ["mexc.com"] },
  { name: "Phantom", key: "phantom", mode: "token", needContext: true, official: ["phantom.app", "phantom.com"] },
];

// mode "token" + needContext: обычные слова (phantom, trezor) — тревога, только если рядом «фишинговое» слово
// (phantom-wallet, trezor-login) или буквы подменены (ph4nt0m)
const CONTEXT = ["login", "signin", "verify", "verification", "secure", "security", "support", "help", "bonus",
  "reward", "rewards", "claim", "airdrop", "drop", "wallet", "app", "connect", "online", "official", "ua", "kyc",
  "auth", "account", "web3", "sync", "restore", "recovery", "update", "suite", "extension", "download", "dapp"];

const VERSIONED_CRYPTO = /^(tron|swap|bridge|scan|wa[li]+et|coin|dex|defi|stake|airdrop|ciaim|bnb|ether|soiana|usdt|uniswap|pancake|sunswap|justiend|crypto|web3)/;

// Легальные сайты, похожие на бренды (другие блокчейн-обозреватели и т.п.)
const KNOWN_LEGIT = ["tonscan.org", "tonscan.com", "btcscan.org", "basescan.org", "polygonscan.com", "arbiscan.io", "mercuryo.io"];

// Государственные и учебные домены не проверяем на двойники (trezor.gov.rs = «казначейство»)
const GOV = /\.(gov|gouv|go|gob|govt|mil|edu|ac)(\.[a-z]{2,3})?$|\.(gov|mil|edu)$/;

// ---------- Punycode (RFC 3492): xn--... -> юникод ----------
function punyDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  let n = 128, i = 0, bias = 72;
  const output = [];
  let basic = input.lastIndexOf("-");
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
  const adapt = (delta, numPoints, first) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (idx >= input.length) throw new Error("bad punycode");
      const c = input.charCodeAt(idx++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
      if (digit >= base) throw new Error("bad punycode");
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

export function toUnicodeHost(host) {
  return host
    .split(".")
    .map((l) => {
      if (!l.startsWith("xn--")) return l;
      try { return punyDecode(l.slice(4)); } catch { return l; }
    })
    .join(".");
}

// ---------- Буквы-двойники -> «скелет» ----------
const CONFUSABLE = {
  // кириллица
  "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
  "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
  "ӏ": "l", "ԛ": "q", "ԝ": "w", "һ": "h", "ь": "b", "п": "n", "г": "r",
  // греческий
  "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
  "υ": "u", "χ": "x", "ω": "w",
  // армянский и прочее
  "ո": "n", "ս": "u", "օ": "o", "ı": "i", "ɑ": "a", "ɡ": "g",
};

export function skeleton(s) {
  let out = "";
  for (const ch of s.normalize("NFKD").toLowerCase()) {
    if (/[̀-ͯ]/.test(ch)) continue; // убрать диакритику (é -> e)
    out += CONFUSABLE[ch] ?? ch;
  }
  return out
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/[0о]/g, "o")
    .replace(/[1l|!]/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/8/g, "b");
}

// ---------- Вспомогательное ----------
export function normalizeHost(host) {
  return String(host || "").toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
}

const isIp = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(":");

// host и все его родительские домены: a.b.example.com -> [a.b.example.com, b.example.com, example.com]
export function hostChain(host) {
  const parts = host.split(".");
  const out = [];
  for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join("."));
  return out;
}

const matchesAny = (host, domains) => hostChain(host).some((h) => domains.has(h));

function levenshteinLE1(a, b) {
  if (a === b) return true;
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  let i = 0, j = 0, edits = 0;
  while (i < la && j < lb) {
    if (a[i] === b[j]) { i++; j++; continue; }
    if (++edits > 1) return false;
    if (la > lb) i++;
    else if (lb > la) j++;
    else if (i + 1 < la && j + 1 < lb && a[i] === b[j + 1] && a[i + 1] === b[j]) { i += 2; j += 2; } // перестановка ab/ba
    else { i++; j++; }
  }
  return edits + (la - i) + (lb - j) <= 1;
}

const OFFICIAL = new Set(BRANDS.flatMap((b) => b.official));
const LEGIT = new Set(KNOWN_LEGIT);
const BRAND_SKEL = BRANDS.map((b) => ({ ...b, skel: skeleton(b.key) }));
const CONTEXT_SKEL = new Set(CONTEXT.map(skeleton));

// ---------- Подделка под известный бренд ----------
export function lookalike(rawHost) {
  const host = normalizeHost(rawHost);
  if (!host || isIp(host)) return null;
  if (matchesAny(host, OFFICIAL) || matchesAny(host, LEGIT) || GOV.test(host)) return null;

  const uni = toUnicodeHost(host);
  const labels = uni.split(".");
  const body = labels.slice(0, -1); // без доменной зоны
  if (!body.length) return null;

  // слова адреса: v3-tronscan.org -> ["v3", "tronscan"]; ярлыки целиком без дефисов -> ["v3tronscan"]
  const rawTokens = body.flatMap((l) => l.split(/[-_]+/)).filter(Boolean);
  const tokens = rawTokens.map(skeleton);
  const glued = body.map((l) => skeleton(l.replace(/[-_]+/g, "")));
  const hasNonAscii = /[^\x00-\x7f]/.test(uni);

  for (const b of BRAND_SKEL) {
    const k = b.skel;
    let hit = false;
    if (b.mode === "token") {
      const i = tokens.indexOf(k);
      if (i >= 0) {
        const disguised = rawTokens[i].toLowerCase() !== b.key; // ph4nt0m, рhantom
        const context = tokens.some((t, j) => j !== i && CONTEXT_SKEL.has(t));
        hit = !b.needContext || disguised || context;
      }
    } else if (glued.some((g) => g.includes(k))) {
      hit = true;
    } else if (k.length >= 8 && !b.noTypo) {
      // опечатки (tronqcan, trosncan, metamsk): слово целиком отличается на 1 символ,
      // первая и последняя буквы совпадают — так «finance» не путается с «binance»
      hit = [...tokens, ...glued].some(
        (t) => t[0] === k[0] && t[t.length - 1] === k[k.length - 1] && levenshteinLE1(t, k)
      );
    }
    if (hit) {
      return { brand: b.name, official: b.official[0], homoglyph: hasNonAscii };
    }
  }

  // Почерк кампаний «v2-tronbridge», «v3-tronscan»: приставка версии + крипто-слово
  for (const label of body) {
    const lt = label.split(/[-_]+/).filter(Boolean);
    const vi = lt.findIndex((t) => /^v\d{1,2}$/i.test(t));
    if (vi < 0 || vi + 1 >= lt.length) continue;
    const next = skeleton(lt[vi + 1]);
    if (!VERSIONED_CRYPTO.test(next)) continue;
    const isTron = next.startsWith("tron");
    return {
      brand: isTron ? "TRON" : "",
      generic: !isTron,
      official: isTron ? "trondao.org" : "",
      homoglyph: hasNonAscii,
    };
  }
  return null;
}

// Популярность не спасает домен из блок-листа, если в нём крипто-слова (cryptogold.exchange, freelitecoin.online)
const CRYPTO_WORDS = /coin|crypt|wallet|swap|airdrop|claim|nft|token|defi|usdt|usdc|trx|tron|exchange|stake|bridge|dex|web3|mint|ledger|seed/;

// ---------- Итоговая проверка ----------
// lists: {
//   index:   DomainIndex — объединённые блок-листы (маска источников на домен)
//   enabled: битовая маска включённых источников
//   popular: HashSet популярных сайтов (Chrome UX Report) — защита от ошибок в блок-листах
//   midpop:  HashSet сайтов из топ-1M, которые есть в блок-листах (для мягкого режима)
//   allow:   HashSet белых списков MetaMask/Polkadot — только точное совпадение записи
//   userAllow, sessionAllow: Set — сайты, которым пользователь доверился
//   block:   Set — простой список (для тестов), считается как PhishDestroy
// }
export function check(rawHost, lists, opts = { lookalike: true }) {
  const host = normalizeHost(rawHost);
  if (!host) return null;
  if (matchesAny(host, OFFICIAL) || matchesAny(host, LEGIT)) return null;
  if (lists.userAllow && matchesAny(host, lists.userAllow)) return null;
  if (lists.sessionAllow && matchesAny(host, lists.sessionAllow)) return null;

  const srcAllowExact = lists.allow ? lists.allow.has(host) : false;
  const look = opts.lookalike !== false && !srcAllowExact ? lookalike(host) : null;
  const enabled = lists.enabled ?? 0xff;

  let best = null;
  for (const h of hostChain(host)) {
    let mask = 0;
    if (lists.index) mask |= lists.index.maskOf(h);
    if (lists.block && lists.block.has(h)) mask |= 1;
    mask &= enabled;
    if (!mask) continue;
    // белые списки MetaMask/Polkadot снимают только саму запись (pages.dev), но не её поддомены
    if (lists.allow && lists.allow.has(h)) continue;
    // ошибки блок-листов на популярных сайтах (line.me, dribbble.com), кроме явно крипто-названий
    if (lists.popular && lists.popular.has(h) && !CRYPTO_WORDS.test(h)) continue;
    // сайт средней популярности (топ-1M Chrome), который отметила только одна база, — скорее ошибка базы
    // или взломанный и уже очищенный сайт: жёлтое предупреждение вместо блокировки
    const single = popcount(mask) === 1;
    const midPopular = single && lists.midpop && lists.midpop.has(h) && !CRYPTO_WORDS.test(h);
    const strong = !midPopular && ((mask & STRONG_MASK) !== 0 || !single);
    const r = { kind: strong ? "list" : "listweak", host, matched: h, sources: mask };
    if (strong) { best = r; break; }
    if (!best) best = r;
  }
  if (best) return { ...(look || {}), ...best };
  if (look) return { kind: "lookalike", host, ...look };
  return null;
}

function popcount(x) {
  let n = 0;
  while (x) { n += x & 1; x >>>= 1; }
  return n;
}

export function parseList(text) {
  const set = new Set();
  for (const line of text.split(/\r?\n/)) {
    const d = line.trim().toLowerCase();
    if (!d || d.startsWith("#") || d.startsWith("!")) continue;
    set.add(d.replace(/^\|\|/, "").replace(/\^$/, "").replace(/^www\./, ""));
  }
  return set;
}
