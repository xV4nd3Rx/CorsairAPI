# 📜 Changelog

## [1.1.0] — 2025-09-25
### Added
- `results.csv` is populated even when `depth=0` (No BruteForce): includes OpenAPI/Swagger candidates (auto-discovery & from HTML), paths from `robots.txt` / `sitemap.xml`, and subdomain probe findings (if enabled).
- New `found` column in `results.csv`: `wordlist`, `openapi-like`, `found-in-html`, `robots`, `sitemap`, `subdomain-probe`.

### Changed
- Unified CSV schema: `url, status, content_type, length, json_like, allow, found`.

## [1.1.0] — 2025-09-25
### Added
- Interactive **Setup your scan** wizard (when flags are not provided): choose `mode` (`stealth` / `medium` / `aggressive`), `user-agent` (`default` / `random` / `custom`), and `depth` (`0` / `1` / `custom`).  
  CLI arguments take precedence.

## [1.1.0] — 2025-09-25
### Changed
- `--depth 0` fully disables wordlist bruteforce; OpenAPI/Swagger auto-discovery, `robots.txt` / `sitemap.xml` parsing, and (optional) subdomain probing remain active.

---
