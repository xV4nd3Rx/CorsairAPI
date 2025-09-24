# 🚀 CorsairAPI - Async OpenAPI-aware Recon & Payload Generator

> 🔎 Asynchronous API reconnaissance, OpenAPI/Swagger discovery and schema-driven payload generation - scoped, configurable, and export-ready for Burp/ZAP and automation pipelines.

---

## 📑 Table of Contents

- [About](#about)  
- [Why](#why)  
- [Features](#features)  
- [Quick Start](#quick-start)  
- [Usage Examples](#usage-examples)  
- [CLI Reference](#cli-reference)  
- [Outputs & Artifacts](#outputs--artifacts)  
- [How OpenAPI Support Works](#how-openapi-support-works)  
- [Wordlist Depth & Safety](#wordlist-depth--safety)  
- [Scan Modes & Tuning](#scan-modes--tuning)  
- [Integration Tips (Burp / Automation)](#integration-tips-burp--automation)  
- [Contributing](#contributing)  
- [License](#license)

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
python api_recon.py -H https://scantarget.com --prefix /api --openapi openapi.yaml
```

Large-depth caution (sampling instead of full expansion):

```bash
python api_recon.py -H https://scantarget.com --prefix /api --depth 4
```

# 🧭 CLI Reference

```text
-H, --target            Target host or URL (required), e.g. -H https://scantarget.com
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

