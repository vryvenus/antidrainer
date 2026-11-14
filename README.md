# AntiDrainer

Browser extension that blocks crypto phishing and wallet-drainer sites and warns about fake look-alike domains.

- Checks every site you open against open databases of scam domains: PhishDestroy, MetaMask, ScamSniffer,
  Polkadot.js (≈600,000 domains) and, optionally, Phishing.Database.
- Detects brand-new fakes that are not in any database yet: `tr0nscan`, `trоnscan` with a Cyrillic “о”,
  `metamask-wallet`, `v2-tronbridge`, `monobank-bonus` and similar.
- Works after redirects (a normal link that bounces you to a phishing domain).
- **Everything is checked locally.** The addresses you visit are never sent anywhere. The only network
  requests are downloads of the public blocklists from GitHub (every 12 hours, skipped if unchanged).

## Protection levels
- **Red — blocked:** the domain is in a trusted database or in several databases at once.
- **Yellow — suspicious:** the domain is only in a database that often flags hacked legitimate sites, or it
  is a well-known site reported by a single database.
- **Yellow — possible fake:** the address contains the name of a known service but is not its official site.

## Install from source
1. Download and unzip this folder.
2. Open `chrome://extensions`, turn on **Developer mode**.
3. Click **Load unpacked** and select the folder that contains `manifest.json`.

## Languages
English, Українська, Русский — chosen automatically from the browser language.

## License
GPL-3.0. Third-party data and licenses: see `THIRD_PARTY_NOTICES.md`.
