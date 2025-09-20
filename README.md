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
python api_recon.py -H https://scantarget.com
