# 🚀 CorsairAPI - Async OpenAPI-aware Recon & Payload Generator

> 🔎 Asynchronous API reconnaissance, OpenAPI/Swagger discovery and schema-driven payload generation - scoped, configurable, and export-ready for Burp/ZAP and automation pipelines.

---

## 📑 Table of Contents

- [About](#about)  
- [Why](#why)  
- [Features](#features)  
- [Quick Start](#quick-start)  
- [Basic Usage](#usage-examples)  
- [CLI Reference](#cli-reference)  
- [Outputs & Artifacts](#outputs--artifacts)  
- [How OpenAPI Support Works](#how-openapi-support-works)  
- [Wordlist Depth & Safety](#wordlist-depth--safety)  
- [Scan Modes & Tuning](#scan-modes--tuning)  
- [Integration Tips (Burp / Automation)](#integration-tips-burp--automation)  
- [Contributing](#contributing)  
- [Contacts](#contacts)  

---

## About

**CorsairAPI** is a pragmatic tool for quickly mapping and exercising API attack surface. It blends passive discovery (robots/sitemaps/HTML), scoped wordlist probing, and OpenAPI-aware payload generation to produce both valid baseline requests and negative test cases for penetration testers and security engineers.

---

## Why

APIs are large, versioned, and frequently only partially documented. Blind brute forcing creates noise and yields many irrelevant results. When available, OpenAPI is the canonical contract - it reveals exact paths, parameter types, required fields, and security schemes. CorsairAPI unites passive discovery, authoritative inventory, and async active probing to reach application logic faster with less noise.

---

## Features

- 🔎 **OpenAPI/Swagger discovery** at common locations and via HTML (Swagger UI)  
- 📚 **OpenAPI 3.x / Swagger 2.0 parsing** (JSON/YAML)  
- 🧩 **Schema-driven payload generation**: baseline (valid) and negative (mutated) payloads  
- 🎯 **Scoped brute-force** under a prefix (`--prefix /api`)  
- 🔢 **Multi-depth wordlist expansion** (`--depth`, default 1) with safety caps and warnings  
- 🌐 **Optional subdomain probing** (disabled when `--prefix` is set)  
- ⚙️ **Configurable modes**: `stealth`, `medium`, `aggressive`  
- 🧰 **Custom/random User-Agent** selection (`--user-agent`)  
- 📦 **Exports**: `results.json`, `results.csv`, `oas_endpoints.txt`, `oas_payloads.jsonl`, `oas_burp.csv`

---

## Quick Start

Run a quick discovery (target passed with `-H`):

```bash
python CorsairAPI.py -H https://scantarget.com
```
Parse a known OpenAPI spec:

```bash
python CorsairAPI.py -H https://scantarget.com --openapi https://scantarget.com/api/openapi.json
```

Random User-Agent example:

```bash
python CorsairAPI.py -H https://scantarget.com --user-agent random
```

## Basic Usage

Basic discovery:

```bash
python CorsairAPI.py -H https://scantarget.com
```

Stealth scan with custom wordlist:

```bash
python CorsairAPI.py -H https://scantarget.com --wordlist endpoints.txt --mode stealth
```

Scoped OpenAPI-driven generation + export:

```bash
python CorsairAPI.py -H https://scantarget.com --prefix /api --openapi openapi.yaml
```

Large-depth caution (sampling instead of full expansion):

```bash
python CorsairAPI.py -H https://scantarget.com --prefix /api --depth 4
```

# CLI Reference

```text
-H, --target           Target host or URL (required), e.g. -H https://scantarget.com
--wordlist, -w         Path to endpoints wordlist (one per line)
--mode, -m             Mode: stealth | medium | aggressive (default: medium)
--user-agent, -a       User-Agent string or "random"
--probe-subdomains     Probe likely subdomains (ignored when --prefix is set)
--subdomains-file      File with custom subdomains (one per line)
--openapi              OpenAPI spec file path or URL (yaml/json)
--no-auto-openapi      Disable auto parse of discovered OpenAPI specs
--prefix               Scope prefix, e.g. /api (strict scope)
--depth                Wordlist brute depth (default: 1)
```
## 📂 Outputs & Artifacts

- 📝 **`results.json`** - full reconnaissance data (OpenAPI candidates, robots/sitemap entries, probed endpoints, subdomain results, etc.).  
- 📊 **`results.csv`** - quick triage table with columns: `url`, `status`, `content_type`, `length`, `json_like`, `allow`.  
- 📄 **`oas_endpoints.txt`** - endpoints (one per line: `METHOD URL`) extracted from parsed OpenAPI specs.  
- 📦 **`oas_payloads.jsonl`** - generated requests (JSONL): objects containing `method`, `url`, `headers`, `body`, `negative_body`, `notes`.  
- 📑 **`oas_burp.csv`** - simplified CSV for Burp/ZAP or pipeline import (columns: `method,url,headers,body`).

---

## 📜 How OpenAPI Support Works

1. **Discovery** - the tool looks for OpenAPI/Swagger specifications at typical locations (e.g. `/openapi.json`, `/swagger.json`, `/api-docs`) and scans HTML (Swagger UI links, script fetches) for spec references.  
2. **Parsing** - it parses `servers`, `paths`, `parameters`, `requestBody`, and `components/securitySchemes` from discovered or provided specs (JSON or YAML).  
3. **Generation** - from schemas it builds:
   - **Baseline payloads** - minimal, valid objects that respect `required`, `type`, `format`, and `example`.  
   - **Negative payloads** - mutated / invalid bodies (wrong types, empty arrays, invalid enum values) to exercise validation and logic.  
4. **Auth placeholders** - when `security` is detected the tool inserts placeholders such as `Authorization: Bearer REPLACE_ME` or `X-API-Key: REPLACE_ME`.  
5. **Export** - ready-to-replay artifacts are saved (`oas_payloads.jsonl`, `oas_burp.csv`, `oas_endpoints.txt`) for manual triage or automated pipelines.

---

## 🔢 Wordlist Depth & Safety

- `--depth=1` (default): use single segments from the wordlist.  
- `--depth ≥ 2`: generate deeper combinations (`w1/w2` for depth=2, etc.).  
- Growth is exponential: combinations ≈ **M^depth** (M = wordlist size).  
- **Safety cap**: the tool enforces a maximum number of generated combinations (e.g. ~100,000). If an expansion would exceed the cap, the tool will **warn** and **sample** a safe subset instead of producing the full Cartesian product.  
- **Recommendation:** use curated, focused wordlists for `depth ≥ 3` to avoid excessive traffic and noise.

---

## 🎚 Scan Modes & Tuning

- **stealth** - low concurrency, randomized delays; best for production-safe scanning.  
- **medium** - balanced default for general recon.  
- **aggressive** - high concurrency, minimal delays; intended for test/staging environments only.  

Tune `--user-agent`, `--mode`, and `--depth` to fit scope and acceptable risk. Monitor for rate-limits (429) and server errors (5xx) and back off if necessary.

---

## 🔗 Integration Tips (Burp / Automation)

- **Burp / ZAP:** import `oas_burp.csv` (or replay via proxy) to populate Proxy → HTTP history, then send interesting requests to Repeater / Intruder / Scanner.  
- **Scripted replay:** use `oas_payloads.jsonl` for programmatic replay (curl, Python, Go). Compare baseline vs negative responses to spot validation and logic issues.  
- **Fuzz / scanners:** feed `oas_endpoints.txt` into targeted fuzzers (ffuf, dirsearch) or auth-logic scanners to expand coverage.  
- **Intruder payloads:** convert `body` or specific fields into payload lists and load them directly into Intruder for automated mutation runs.

---

## 🤝 Contributing

Contributions are welcome. Useful areas:
- Additional discovery heuristics and heuristics for non-standard spec locations; 
- Richer payload mutation strategies and smarter negative-case generation;
- Postman/Insomnia export, HAR export, or direct Burp plugin helpers;
- GraphQL introspection and query/mutation generation.

Fork the repo, create a feature branch, and open a pull request with tests or examples where applicable.

## 📬 Contacts

- [LinkedIn](https://www.linkedin.com/in/yurii-tsarienko-a1453aa4)
- [SecForgeHub Telegram](https://t.me/SecForgeHub)

