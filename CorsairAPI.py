from __future__ import annotations
import argparse
import asyncio
import sys
import json
import csv
import re
import random
import time
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse, urlencode, quote
from itertools import product
import aiohttp
from aiohttp import ClientTimeout
try:
    import yaml
except Exception:
    yaml = None

DEFAULT_WORDLIST = [
    "users","user","accounts","auth","login","logout","refresh",
    "books","books/list","books/{id}","orders","orders/{id}",
    "admin","status","health","metrics","search","upload","download",
    "profile","settings","config","payments","webhook","callback",
    "graphql","graphiql","altair","playground","docs","doc","swagger"
]
COMMON_API_PREFIXES = [
    "/api/","/api","/api/v1","/api/v2","/v1/","/v1","/v2/","/v2","/v3/",
    "/rest/","/rest","/swagger","/swagger.json","/swagger-ui","/doc","/docs",
    "/graphql","/graphiql","/altair","/playground","/api/v3","/services/",
    "/internal/","/api-docs","/openapi.json","/openapi.yaml"
]
DEFAULT_SUBDOMAIN_HINTS = [
    "api","uat","dev","test","staging","stage","developer","developer-api",
    "developer-%s","api-%s"
]
RANDOM_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "curl/7.88.1","Wget/1.21.3 (linux-gnu)","Python-urllib/3.11","python-requests/2.31.0",
    "PostmanRuntime/7.32.3","Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
]
MODE_PRESETS = {
    "stealth":{"concurrency":5,"delay":(0.5,1.5),"timeout":20,"retries":1},
    "medium":{"concurrency":20,"delay":(0.0,0.3),"timeout":15,"retries":1},
    "aggressive":{"concurrency":60,"delay":(0.0,0.0),"timeout":10,"retries":0}
}

class Progress:
    def __init__(self,total:int,label:str="Progress"):
        self.total = max(1,total)
        self.label = label
        self.start = time.time()
        self.done = 0
        self.last_len = 0
    def update(self,step:int=1):
        self.done += step
        now = time.time()
        elapsed = now - self.start
        rate = self.done/elapsed if elapsed>0 else 0
        remain = (self.total - self.done)/rate if rate>0 else 0
        pct = int(self.done*100/self.total)
        bar_len = 24
        fill = int(bar_len*pct/100)
        bar = "#"*fill + "-"*(bar_len-fill)
        line = f"{self.label} [{bar}] {pct:3d}%  {self.done}/{self.total}  elapsed {int(elapsed)}s  ETA {int(remain)}s"
        pad = " " * max(0,self.last_len - len(line))
        self.last_len = len(line)
        sys.stdout.write("\r"+line+pad)
        sys.stdout.flush()
        if self.done>=self.total:
            sys.stdout.write("\n")
            sys.stdout.flush()

def normalize_url(base: str) -> str:
    if not base.startswith("http"):
        base = "https://" + base
    return base.rstrip("/")

def normalize_prefix(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    p = p.strip()
    if not p:
        return None
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/")

def load_wordlist(path: Optional[str]) -> List[str]:
    if not path:
        return DEFAULT_WORDLIST.copy()
    p = Path(path)
    if not p.exists():
        return DEFAULT_WORDLIST.copy()
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def load_subdomains_file(path: Optional[str]) -> List[str]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def pick_user_agent(ua_arg: str) -> str:
    if not ua_arg:
        return RANDOM_USER_AGENTS[0]
    if ua_arg.lower() == "random":
        return random.choice(RANDOM_USER_AGENTS)
    return ua_arg

def make_sem_and_delay(mode: str):
    cfg = MODE_PRESETS.get(mode, MODE_PRESETS["medium"])
    return asyncio.Semaphore(cfg["concurrency"]), cfg["delay"], cfg["timeout"], cfg["retries"]

async def fetch_text(session: aiohttp.ClientSession, url: str, timeout: int) -> Tuple[Optional[int], Optional[Dict[str,str]], Optional[str]]:
    try:
        async with session.get(url, timeout=ClientTimeout(total=timeout), allow_redirects=True) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, dict(resp.headers), text
    except Exception:
        return None, None, None

async def try_openapi_locations(session: aiohttp.ClientSession, base: str, timeout: int, scope_prefix: Optional[str]):
    found = []
    if scope_prefix:
        cand = [
            scope_prefix,
            f"{scope_prefix}/openapi.json",
            f"{scope_prefix}/openapi.yaml",
            f"{scope_prefix}/swagger.json",
            f"{scope_prefix}/api-docs",
            f"{scope_prefix}/swagger/v1/swagger.json",
            f"{scope_prefix}/v2/api-docs"
        ]
    else:
        cand = COMMON_API_PREFIXES + ["/swagger/v1/swagger.json","/v2/api-docs"]
    seen = set()
    for p in cand:
        url = urljoin(base + "/", p.lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        status, headers, text = await fetch_text(session, url, timeout)
        if status and status < 500 and text:
            if ("openapi" in text.lower()) or ("swagger" in text.lower()) or (url.endswith(".json") and text.strip().startswith("{")):
                found.append({"url": url, "status": status, "hint": "openapi-like"})
    return found

def extract_spec_url_from_html(html: str, base: str) -> List[str]:
    urls = set()
    base_host = urlparse(base).hostname
    for m in re.finditer(r'(https?://[^\s"\'<>]+|["\'](/[^"\']*openapi[^"\']*)["\'])', html, re.IGNORECASE):
        u = m.group(1)
        if u.startswith('"') or u.startswith("'"):
            u = u.strip("\"'")
        if u.startswith("/"):
            u = urljoin(base, u)
        try:
            parsed = urlparse(u)
            if parsed.hostname and base_host and parsed.hostname != base_host and not parsed.hostname.endswith("." + base_host):
                continue
        except Exception:
            continue
        urls.add(u)
    for m in re.finditer(r'fetch\(\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
        u = m.group(1)
        if u.startswith("/"):
            u = urljoin(base, u)
        elif not u.startswith("http"):
            u = urljoin(base + "/", u)
        try:
            parsed = urlparse(u)
            if parsed.hostname and base_host and parsed.hostname != base_host and not parsed.hostname.endswith("." + base_host):
                continue
        except Exception:
            continue
        if any(tok in u.lower() for tok in ("openapi","swagger","api-docs",".json",".yaml",".yml")):
            urls.add(u)
    return list(urls)

def parse_robots_for_paths(text: str, base: str) -> List[str]:
    paths = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                p = parts[1].strip()
                if p and p != "/":
                    paths.add(urljoin(base + "/", p.lstrip("/")))
    return list(paths)

def parse_sitemap_for_paths(text: str) -> List[str]:
    paths = set()
    for m in re.finditer(r'<loc>([^<]+)</loc>', text, re.IGNORECASE):
        loc = m.group(1).strip()
        if loc:
            paths.add(loc)
    return list(paths)

async def fetch_robots_and_sitemap(session: aiohttp.ClientSession, base: str, timeout: int):
    results = []
    for rel in ("robots.txt","sitemap.xml"):
        url = urljoin(base + "/", rel)
        try:
            async with session.get(url, timeout=ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    results.append({"url": url, "status": resp.status, "text": text})
        except Exception:
            pass
    return results

async def check_single_endpoint(session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore, timeout: int, delay_range: tuple, retries: int):
    async with sem:
        if delay_range and (delay_range[0] or delay_range[1]):
            await asyncio.sleep(random.uniform(delay_range[0], delay_range[1]))
        attempt = 0
        while attempt <= retries:
            try:
                async with session.request("GET", url, timeout=ClientTimeout(total=timeout), allow_redirects=True) as resp:
                    body = await resp.read()
                    text_sample = (body[:800].decode('utf-8', errors='ignore')) if body else ""
                    content_type = resp.headers.get("Content-Type", "")
                    return {
                        "url": str(resp.url),
                        "status": resp.status,
                        "content_type": content_type,
                        "length": len(body),
                        "title_snippet": (re.search(r'<title>(.*?)</title>', text_sample, re.IGNORECASE).group(1) if re.search(r'<title>(.*?)</title>', text_sample, re.IGNORECASE) else "")[:120],
                        "json_like": ("application/json" in content_type.lower()) or ("{" in text_sample[:50]),
                        "headers": dict(resp.headers)
                    }
            except asyncio.CancelledError:
                raise
            except Exception:
                attempt += 1
                if attempt > retries:
                    return None
                await asyncio.sleep(0.2 * attempt)
    return None

def expand_wordlist_paths(wordlist: List[str], depth: int, max_combinations: int = 100000) -> List[str]:
    if depth <= 0:
        return []
    base = [w.strip().strip("/") for w in wordlist if w and w.strip()]
    base = [b for b in base if b]
    if not base:
        return []
    out = set(base)
    if depth <= 1:
        return sorted(out)
    total_added = len(out)
    for d in range(2, depth + 1):
        combos = len(base) ** d
        if total_added + combos > max_combinations:
            allowed = max(0, max_combinations - total_added)
            if allowed <= 0:
                break
            sampled = set()
            tries = 0
            while len(sampled) < allowed and tries < allowed * 10:
                tup = tuple(random.choice(base) for _ in range(d))
                sampled.add("/".join(tup))
                tries += 1
            out.update(sampled)
            total_added = len(out)
            break
        for tup in product(base, repeat=d):
            out.add("/".join(tup))
        total_added = len(out)
    return sorted(out)

async def probe_wordlist(session: aiohttp.ClientSession, base: str, prefix: str, wordlist_paths: List[str], sem: asyncio.Semaphore, timeout: int, delay_range: tuple, retries: int, progress: Optional[Progress]=None):
    results = []
    tasks = []
    for rel in wordlist_paths:
        path = prefix.rstrip("/") + "/" + rel.lstrip("/")
        url = urljoin(base + "/", path.lstrip("/"))
        tasks.append(check_single_endpoint(session, url, sem, timeout, delay_range, retries))
    if not tasks:
        return []
    for fut in asyncio.as_completed(tasks):
        res = await fut
        if res:
            results.append(res)
        if progress:
            progress.update(1)
    return results

async def probe_subdomains(base: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore, timeout: int, delay_range: tuple, retries: int, extra_subdomains: List[str]):
    parsed = urlparse(base)
    host = parsed.hostname
    if not host:
        return []
    candidates = set()
    for hint in DEFAULT_SUBDOMAIN_HINTS:
        if "%s" in hint:
            candidates.add(hint % (host.split(".", 1)[0]))
        else:
            candidates.add(hint)
    for s in extra_subdomains:
        candidates.add(s)
    results = []
    tasks = []
    for sub in candidates:
        fqdn = f"{sub}.{host}"
        for scheme in ("https://","http://"):
            url = f"{scheme}{fqdn}/"
            tasks.append(check_single_endpoint(session, url, sem, timeout, delay_range, retries))
    completed = await asyncio.gather(*tasks, return_exceptions=True)
    for c in completed:
        if isinstance(c, dict) and c:
            results.append(c)
    return results

def _ensure_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]

def pick_server_url(spec: Dict[str,Any], fallback_base: str) -> str:
    if not isinstance(spec, dict):
        return fallback_base.rstrip("/")
    servers = spec.get("servers") or []
    for s in servers:
        if isinstance(s, dict):
            u = s.get("url")
            if u and isinstance(u, str) and u.startswith("http"):
                return u.rstrip("/")
    if "host" in spec:
        schemes = spec.get("schemes") or ["https"]
        base_path = spec.get("basePath", "")
        scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
        return f"{scheme}://{spec['host']}{base_path}".rstrip("/")
    return fallback_base.rstrip("/")

def example_for_primitive(schema: Dict[str,Any], negative: bool=False):
    t = (schema or {}).get("type")
    fmt = (schema or {}).get("format")
    enum = (schema or {}).get("enum")
    if enum:
        return enum[0] if not negative else "___INVALID_ENUM___"
    if t == "string" or (t is None and not schema.get("properties") and not schema.get("items")):
        if negative:
            return ""
        if fmt == "uuid": return "00000000-0000-4000-8000-000000000000"
        if fmt == "date": return "2025-01-01"
        if fmt == "date-time": return "2025-01-01T00:00:00Z"
        if fmt == "email": return "user@example.com"
        return "test"
    if t == "integer": return 0 if not negative else -999999
    if t == "number": return 1.23 if not negative else 1e309
    if t == "boolean": return True if not negative else "not_bool"
    return "test"

def build_example_from_schema(schema: Dict[str,Any], negative: bool=False):
    if not isinstance(schema, dict):
        return "test"
    if "allOf" in schema:
        merged = {}
        last = None
        for sub in schema["allOf"]:
            v = build_example_from_schema(sub, negative)
            last = v
            if isinstance(v, dict):
                merged.update(v)
        return merged if merged else last
    if "oneOf" in schema or "anyOf" in schema:
        arr = schema.get("oneOf") or schema.get("anyOf") or []
        return build_example_from_schema(arr[0], negative) if arr else "test"
    t = schema.get("type")
    if t == "object" or "properties" in schema:
        out = {}
        props = schema.get("properties") or {}
        req = set(schema.get("required") or [])
        for k, subs in props.items():
            if (not negative and req and k not in req):
                continue
            out[k] = build_example_from_schema(subs, negative)
        if not out and props:
            for i,(k,subs) in enumerate(props.items()):
                if i>1: break
                out[k] = build_example_from_schema(subs, negative)
        return out if out else {"example":"test"}
    if t == "array":
        item = build_example_from_schema(schema.get("items") or {}, negative)
        return [item] if not negative else []
    return example_for_primitive(schema, negative)

def schema_from_media(media: Dict[str,Any]) -> Dict[str,Any]:
    if not isinstance(media, dict):
        return {}
    return media.get("schema") or {}

def collect_oas_operations(spec: Dict[str,Any]) -> List[Dict[str,Any]]:
    ops = []
    paths = spec.get("paths") or {}
    for raw_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in ("get","post","put","patch","delete","options","head"):
                continue
            ops.append({"path": raw_path, "method": method.upper(), "op": op})
    return ops

def extract_params(op: Dict[str,Any]) -> Dict[str,Any]:
    out = {"path":{}, "query":{}, "header":{}}
    for p in _ensure_list(op.get("parameters")):
        name = p.get("name"); where = p.get("in"); schema = p.get("schema") or {}
        ex = p.get("example"); dv = p.get("default")
        value = ex if ex is not None else (dv if dv is not None else build_example_from_schema(schema, negative=False))
        if name and where in out:
            out[where][name] = value
    return out

def extract_request_body(op: Dict[str,Any]):
    rb = op.get("requestBody")
    if not rb:
        return None, None
    content = rb.get("content") or {}
    if "application/json" in content:
        return schema_from_media(content["application/json"]), "application/json"
    for ctype, desc in content.items():
        return schema_from_media(desc), ctype
    return None, None

def generate_requests_from_oas(spec: Dict[str,Any], fallback_base: str, scope_prefix: Optional[str]) -> List[Dict[str,Any]]:
    if not isinstance(spec, dict):
        return []
    base_url = pick_server_url(spec, fallback_base)
    ops = collect_oas_operations(spec)
    reqs = []
    for o in ops:
        op = o["op"]; method = o["method"]; raw_path = o["path"]
        if scope_prefix and not raw_path.startswith(scope_prefix):
            continue
        params = extract_params(op)
        path_rendered = raw_path
        for name, val in params["path"].items():
            path_rendered = path_rendered.replace("{%s}"%name, quote(str(val), safe=""))
        url = base_url.rstrip("/") + "/" + path_rendered.lstrip("/")
        headers = {}
        sec = op.get("security") or spec.get("security")
        if sec:
            comps = (spec.get("components") or {}).get("securitySchemes", {})
            if any(d.get("type")=="http" and d.get("scheme")=="bearer" for d in comps.values()):
                headers["Authorization"] = "Bearer REPLACE_ME"
            elif any(d.get("type")=="apiKey" and d.get("in")=="header" for d in comps.values()):
                for _, d in comps.items():
                    if d.get("type")=="apiKey" and d.get("in")=="header":
                        headers[d.get("name","X-API-Key")] = "REPLACE_ME"; break
        qs = params["query"]; query_str = ("?"+urlencode(qs, doseq=True)) if qs else ""
        body_schema, ctype = extract_request_body(op)
        body_baseline = body_negative = None
        if body_schema:
            body_baseline = build_example_from_schema(body_schema, negative=False)
            body_negative = build_example_from_schema(body_schema, negative=True)
            if ctype and "json" in ctype:
                headers["Content-Type"] = ctype
        reqs.append({
            "method": method,
            "url": url + query_str,
            "headers": headers,
            "body": body_baseline,
            "negative_body": body_negative,
            "notes": "generated-from-openapi"
        })
    return reqs

def load_openapi_from_path(path: str) -> Dict[str,Any]:
    t = Path(path).read_text(encoding="utf-8", errors="ignore")
    try:
        parsed = json.loads(t)
    except Exception:
        if yaml is None:
            raise RuntimeError("PyYAML is required to parse YAML OpenAPI")
        parsed = yaml.safe_load(t)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"OpenAPI: parsed content from file '{path}' is not a mapping/dict (type={type(parsed).__name__})")
    return parsed

def load_openapi_from_url(text: str) -> Dict[str,Any]:
    if text is None:
        raise RuntimeError("OpenAPI: empty response content")
    s = text.lstrip()
    if s.startswith("{"):
        parsed = json.loads(text)
    else:
        if yaml is None:
            raise RuntimeError("PyYAML is required to parse YAML OpenAPI")
        parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict):
        raise RuntimeError("OpenAPI: parsed content from URL is not a mapping/dict")
    return parsed

async def run_recon(base: str, wordlist: List[str], depth: int, mode: str, ua: str, probe_subs: bool, subdomains_custom: List[str], openapi_arg: Optional[str], auto_parse_discovered: bool, scope_prefix: Optional[str]):
    base = normalize_url(base)
    scope_prefix = normalize_prefix(scope_prefix)
    sem, delay_range, timeout, retries = make_sem_and_delay(mode)
    headers = {"User-Agent": ua}
    results = {"base": base, "mode": mode, "openapi": [], "robots_sitemap": [], "probed": [], "wordlist": [], "subdomains": []}
    effective_subdomain_probe = (probe_subs and not scope_prefix)
    wl_paths = expand_wordlist_paths(wordlist, depth)
    parse_errors: List[str] = []
    parsed_specs_count = 0
    async with aiohttp.ClientSession(headers=headers) as session:
        found_specs = await try_openapi_locations(session, base, timeout, scope_prefix)
        results["openapi"].extend(found_specs)
        status, hdrs, html = await fetch_text(session, base + "/", timeout)
        if status and html:
            candidates = extract_spec_url_from_html(html, base)
            for c in candidates:
                if scope_prefix:
                    try:
                        up = urlparse(c)
                        if not up.path.startswith(scope_prefix):
                            continue
                    except Exception:
                        pass
                s, h, t = await fetch_text(session, c, timeout)
                if s and t:
                    results["openapi"].append({"url": c, "status": s, "hint": "found-in-html"})
        r_and_s = await fetch_robots_and_sitemap(session, base, timeout)
        results["robots_sitemap"].extend(r_and_s)
        for item in r_and_s:
            if item["url"].endswith("robots.txt"):
                for u in parse_robots_for_paths(item["text"], base):
                    if (not scope_prefix) or urlparse(u).path.startswith(scope_prefix):
                        results["probed"].append({"url": u, "source": "robots"})
            elif item["url"].endswith("sitemap.xml"):
                for u in parse_sitemap_for_paths(item["text"]):
                    if (not scope_prefix) or urlparse(u).path.startswith(scope_prefix):
                        results["probed"].append({"url": u, "source": "sitemap"})
        prefixes = [scope_prefix] if scope_prefix else COMMON_API_PREFIXES
        total_tasks = 0
        for pref in prefixes:
            if not pref:
                continue
            total_tasks += len(wl_paths)
        progress = Progress(total_tasks if total_tasks>0 else 1, label="Wordlist")
        if wl_paths:
            wl_results_all = []
            for pref in prefixes:
                if not pref:
                    continue
                bucket = await probe_wordlist(session, base, pref, wl_paths, sem, timeout, delay_range, retries, progress=progress)
                wl_results_all.append(bucket)
            for bucket in wl_results_all:
                results["wordlist"].extend(bucket)
        else:
            results["wordlist"] = []
        to_probe = [item["url"] for item in results["wordlist"] if item and item.get("url")]
        async def probe_options(u):
            async with sem:
                if delay_range and (delay_range[0] or delay_range[1]):
                    await asyncio.sleep(random.uniform(delay_range[0], delay_range[1]))
                try:
                    async with session.request("OPTIONS", u, timeout=ClientTimeout(total=10)) as resp:
                        return {"url": u, "options_status": resp.status, "allow": resp.headers.get("Allow", "")}
                except Exception:
                    return None
        if to_probe:
            options_results = await asyncio.gather(*[probe_options(u) for u in to_probe])
            for orr in options_results:
                if orr:
                    for w in results["wordlist"]:
                        if w["url"] == orr["url"]:
                            w.update(orr)
        if effective_subdomain_probe:
            sub_results = await probe_subdomains(base, session, sem, timeout, delay_range, retries, subdomains_custom)
            results["subdomains"].extend(sub_results)
        specs_to_parse: List[Dict[str,Any]] = []
        if openapi_arg:
            if re.match(r"^https?://", openapi_arg):
                s, h, t = await fetch_text(session, openapi_arg, timeout)
                if t:
                    try:
                        parsed = load_openapi_from_url(t)
                        if isinstance(parsed, dict):
                            specs_to_parse.append(parsed); parsed_specs_count += 1
                    except Exception as e:
                        parse_errors.append(f"{openapi_arg} | {e}")
            else:
                try:
                    parsed = load_openapi_from_path(openapi_arg)
                    if isinstance(parsed, dict):
                        specs_to_parse.append(parsed); parsed_specs_count += 1
                except Exception as e:
                    parse_errors.append(f"{openapi_arg} | {e}")
        if auto_parse_discovered:
            for item in results["openapi"]:
                u = item.get("url")
                if not u:
                    continue
                s, h, t = await fetch_text(session, u, timeout)
                if not t:
                    continue
                try:
                    spec = load_openapi_from_url(t)
                    if isinstance(spec, dict):
                        specs_to_parse.append(spec); parsed_specs_count += 1
                except Exception as e:
                    parse_errors.append(f"{u} | {e}")
    seen = set()
    oas_payloads: List[Dict[str,Any]] = []
    oas_endpoints: List[str] = []
    for spec in specs_to_parse:
        reqs = generate_requests_from_oas(spec, base, scope_prefix)
        for r in reqs:
            key = (r["method"], r["url"])
            if key in seen:
                continue
            seen.add(key)
            oas_payloads.append(r)
            oas_endpoints.append(f"{r['method']} {r['url']}")
    return results, oas_payloads, sorted(set(oas_endpoints)), parse_errors, parsed_specs_count

def save_results(results: dict, outdir: str):
    out_path = Path(outdir)
    out_path.mkdir(parents=True, exist_ok=True)
    rows = []
    for w in results.get("wordlist", []):
        rows.append({
            "url": w.get("url"),
            "status": w.get("status"),
            "content_type": w.get("content_type"),
            "length": w.get("length"),
            "json_like": w.get("json_like"),
            "allow": w.get("allow", ""),
            "found": "wordlist"
        })
    for o in results.get("openapi", []):
        rows.append({
            "url": o.get("url"),
            "status": o.get("status"),
            "content_type": "",
            "length": "",
            "json_like": "",
            "allow": "",
            "found": o.get("hint") or "openapi-candidate"
        })
    for p in results.get("probed", []):
        rows.append({
            "url": p.get("url"),
            "status": "",
            "content_type": "",
            "length": "",
            "json_like": "",
            "allow": "",
            "found": p.get("source") or "robots/sitemap"
        })
    for s in results.get("subdomains", []):
        rows.append({
            "url": s.get("url"),
            "status": s.get("status"),
            "content_type": s.get("content_type"),
            "length": s.get("length"),
            "json_like": s.get("json_like"),
            "allow": "",
            "found": "subdomain-probe"
        })
    with open(out_path / "results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    fieldnames = ["url","status","content_type","length","json_like","allow","found"]
    with open(out_path / "results.csv", "w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

def save_oas_exports(oas_payloads: List[Dict[str,Any]], oas_endpoints: List[str], outdir: str):
    out_path = Path(outdir)
    out_path.mkdir(parents=True, exist_ok=True)
    with open(out_path / "oas_endpoints.txt", "w", encoding="utf-8") as f:
        for line in oas_endpoints:
            f.write(line + "\n")
    with open(out_path / "oas_payloads.jsonl", "w", encoding="utf-8") as f:
        for r in oas_payloads:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(out_path / "oas_burp.csv", "w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=["method","url","headers","body"])
        writer.writeheader()
        for r in oas_payloads:
            writer.writerow({
                "method": r["method"],
                "url": r["url"],
                "headers": json.dumps(r.get("headers") or {}),
                "body": json.dumps(r.get("body")) if r.get("body") is not None else ""
            })

def parse_args():
    ap = argparse.ArgumentParser(description="API Recon (async)")
    ap.add_argument("-H","--target",required=True,help="Target host or URL")
    ap.add_argument("--wordlist","-w",help="Path to endpoints wordlist")
    ap.add_argument("--mode","-m",choices=["stealth","medium","aggressive"],default="medium",help="Intensity mode")
    ap.add_argument("--user-agent","-a",default="APIRecon/1.0",help='User-Agent string or "random"')
    ap.add_argument("--probe-subdomains",action="store_true",help="Probe likely subdomains (ignored if --prefix is set)")
    ap.add_argument("--subdomains-file",help="Custom subdomains list")
    ap.add_argument("--openapi",help="OpenAPI spec file path or URL (yaml/json)")
    ap.add_argument("--no-auto-openapi",action="store_true",help="Disable auto parse of discovered OpenAPI specs")
    ap.add_argument("--prefix",help="Scope prefix, e.g. /api")
    ap.add_argument("--depth",type=int,default=1,help="Bruteforce depth (0 to skip)")
    return ap.parse_args()

def _cli_flag_present(names: List[str]) -> bool:
    argv = sys.argv[1:]
    for n in names:
        if n in argv:
            return True
        for a in argv:
            if a.startswith(n + "="):
                return True
    return False

def interactive_setup(args: argparse.Namespace) -> argparse.Namespace:
    mode_provided = _cli_flag_present(["--mode","-m"])
    ua_provided = _cli_flag_present(["--user-agent","-a","--user_agent"])
    depth_provided = _cli_flag_present(["--depth"])
    if not any((mode_provided, ua_provided, depth_provided)):
        print("Setup Your Scan - Interactive Mode (press Enter to accept defaults).")
    else:
        print("Setup Your Scan - Interactive prompts for parameters not provided via CLI.")
    if not mode_provided:
        while True:
            print("\nSelect mode:\n[1] stealth\n[2] medium (default)\n[3] aggressive")
            choice = input("Choose [1-3] (default 2): ").strip()
            if choice == "" or choice == "2":
                args.mode = "medium"; break
            if choice == "1":
                args.mode = "stealth"; break
            if choice == "3":
                args.mode = "aggressive"; break
            print("Invalid choice, try again.")
    else:
        if args.mode not in MODE_PRESETS:
            print(f"[!] Warning: provided mode '{args.mode}' not recognized. Falling back to 'medium'.")
            args.mode = "medium"
    if not ua_provided:
        while True:
            print("\nUser-Agent selection:\n[1] Default (APIRecon/1.0)\n[2] Random\n[3] Custom")
            choice = input("Choose [1-3] (default 1): ").strip()
            if choice == "" or choice == "1":
                args.user_agent = "APIRecon/1.0"; break
            if choice == "2":
                args.user_agent = "random"; break
            if choice == "3":
                ua = input("Enter custom User-Agent string: ").strip()
                if ua:
                    args.user_agent = ua; break
                else:
                    print("Empty UA, try again.")
            else:
                print("Invalid choice, try again.")
    else:
        if not args.user_agent:
            args.user_agent = "APIRecon/1.0"
    if not depth_provided:
        while True:
            print("\nDepth selection:\n[1] 0 - No BruteForce\n[2] 1 - One Level BruteForce (default)\n[3] Custom (enter number)")
            choice = input("Choose [1-3] (default 2): ").strip()
            if choice == "" or choice == "2":
                args.depth = 1; break
            if choice == "1":
                args.depth = 0; break
            if choice == "3":
                val = input("Enter integer depth (0 to skip brute, >=1 to enable): ").strip()
                try:
                    d = int(val)
                    if d < 0:
                        print("Depth cannot be negative."); continue
                    args.depth = d; break
                except ValueError:
                    print("Not an integer, try again.")
            else:
                print("Invalid choice, try again.")
    else:
        try:
            i = int(args.depth)
            if i < 0:
                print("[!] Warning: depth < 0 not allowed. Using 1.")
                args.depth = 1
        except Exception:
            print("[!] Warning: depth not an integer. Using 1.")
            args.depth = 1
    print("\nConfiguration:")
    ua_display = args.user_agent if args.user_agent != "random" else "random (will pick one at runtime)"
    print(f"  Mode: {args.mode}")
    print(f"  User-Agent: {ua_display}")
    print(f"  Depth: {args.depth}\n")
    return args

def main():
    args = parse_args()
    if sys.stdin.isatty():
        args = interactive_setup(args)
    wordlist = load_wordlist(args.wordlist)
    custom_subs = load_subdomains_file(args.subdomains_file)
    ua = pick_user_agent(args.user_agent)
    mode = args.mode
    auto_parse = not args.no_auto_openapi
    print(f"[+] Target: {args.target}")
    print(f"[+] Mode: {mode} | UA: {ua} | Wordlist: {len(wordlist)} | Prefix: {args.prefix or '(none)'} | Depth: {args.depth}")
    if args.prefix:
        print("[i] Prefix set — subdomain probing will be disabled to keep strict scope.")
    results, oas_payloads, oas_endpoints, parse_errors, parsed_specs_count = asyncio.run(
        run_recon(
            base=args.target,
            wordlist=wordlist,
            depth=args.depth,
            mode=mode,
            ua=ua,
            probe_subs=args.probe_subdomains,
            subdomains_custom=custom_subs,
            openapi_arg=args.openapi,
            auto_parse_discovered=auto_parse,
            scope_prefix=args.prefix,
        )
    )
    parsed_target = urlparse(normalize_url(args.target))
    hostname = parsed_target.hostname or "results"
    outdir = f"{hostname}_results"
    Path(outdir).mkdir(parents=True, exist_ok=True)
    save_results(results, outdir)
    save_oas_exports(oas_payloads, oas_endpoints, outdir)
    print(f"[+] Recon saved in folder: {outdir}")
    print("[+] Done.")

if __name__ == "__main__":
    main()
