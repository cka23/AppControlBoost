"""SentinelOne Management API helpers + inventory/rule logic for AppControlUI.

Adapted from s1_app_inventory.py (inventory + Event Search enrichment + binary
matching) and app.py (defensive error handling, scoped pagination).
No web framework imports here so the logic is easy to test.
"""
import os
import random
import re
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT = 40

# Header of sample-nac-rules.csv - the CSV output honours this exactly.
RULE_COLUMNS = [
    "Rule Name", "Description", "Rule Action", "OS Type", "Propagation",
    "Publisher", "Path", "Binary Identity", "Hash SHA-256", "Process",
    "Parent Process", "Exception Publisher", "Exception Path",
    "Exception Binary Identity", "Exception Hash SHA-256",
    "Exception Process", "Exception Parent Process",
]


class Cancelled(Exception):
    """Raised inside a background job when the user pressed Cancel."""


class S1Error(Exception):
    def __init__(self, message, status=502):
        super().__init__(message)
        self.message, self.status = message, status


def normalize_base_url(raw, allowed_suffixes=(".sentinelone.net",)):
    if not raw or not raw.strip():
        raise S1Error("Console URL is required.", 400)
    url = re.sub(r"/web/api.*$", "", raw.strip().rstrip("/"), flags=re.I)
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if not host or "." not in host:
        raise S1Error("That doesn't look like a valid console URL. "
                      "Example: https://usea1-purple.sentinelone.net", 400)
    if p.scheme != "https":
        raise S1Error("The console URL must use https.", 400)
    if allowed_suffixes and not any(host.endswith(s.lower()) for s in allowed_suffixes):
        raise S1Error(f"Console host must end with one of: {', '.join(allowed_suffixes)}", 400)
    return f"https://{p.netloc}"


def _detail(resp):
    try:
        body = resp.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        errs = body.get("errors")
        if isinstance(errs, list) and errs:
            f = errs[0]
            if isinstance(f, dict):
                return f.get("detail") or f.get("title") or ""
            return str(f)
        if isinstance(errs, str):
            return errs
        return body.get("detail") or body.get("message") or ""
    return ""


class S1:
    def __init__(self, base_url, token, verify=True):
        self.base, self.token, self.verify = base_url, token, verify
        self.session = requests.Session()
        self._lock = threading.Lock()
        self._pause_until = 0.0   # shared cool-down: when the console says 429, every worker backs off together

    def _wait(self):
        while True:
            d = self._pause_until - time.time()
            if d <= 0:
                return
            time.sleep(min(d, 2))

    def _backoff(self, resp, attempt):
        try:
            d = float(resp.headers.get("Retry-After", ""))
        except ValueError:
            d = min(2 ** (attempt + 1), 30)
        d = min(max(d, 1), 60) + random.random()
        with self._lock:
            self._pause_until = max(self._pause_until, time.time() + d)

    def request(self, method, path, params=None, body=None, bearer=False,
                headers=None, retries=4):
        h = {"Authorization": ("Bearer " if bearer else "ApiToken ") + self.token,
             "Accept": "application/json", "Content-Type": "application/json"}
        h.update(headers or {})
        for attempt in range(max(retries, 8)):
            self._wait()
            try:
                r = self.session.request(method, self.base + path, params=params,
                                         json=body, headers=h, timeout=REQUEST_TIMEOUT,
                                         verify=self.verify)
            except requests.exceptions.SSLError:
                raise S1Error("TLS error talking to the console. If you are behind a "
                              "proxy, set REQUESTS_CA_BUNDLE or S1_VERIFY_TLS=false.", 502)
            except requests.exceptions.ConnectionError:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt); continue
                raise S1Error(f"Could not reach {self.base}. Check the URL.", 502)
            except requests.exceptions.Timeout:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt); continue
                raise S1Error("Console request timed out.", 504)
            if r.status_code == 429 and attempt < 7:      # rate limited: pause ALL workers, then retry
                self._backoff(r, attempt); continue
            if r.status_code in (500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(min(2 ** attempt, 8)); continue
            if r.status_code == 401:
                raise S1Error("Invalid or expired API token.", 401)
            if r.status_code == 403:
                raise S1Error(f"Token lacks permission for {path}. {_detail(r)}".strip(), 403)
            if r.status_code >= 400:
                raise S1Error(f"{r.status_code} on {path}. {_detail(r)}".strip(), r.status_code)
            try:
                return r.json() if r.content else {}, r.headers
            except ValueError:
                raise S1Error("Console returned non-JSON. Is the URL correct?", 502)

    def get(self, path, params=None):
        return self.request("GET", path, params=params)[0]

    def paginate(self, path, params=None, limit=100, max_items=None):
        params = dict(params or {}, limit=limit)
        n = 0
        while True:
            js = self.get(path, params)
            data = js.get("data", [])
            if isinstance(data, dict):  # e.g. /sites -> {data:{sites:[...]}}
                data = data.get("sites") or data.get("accounts") or []
            for item in data:
                yield item
                n += 1
                if max_items and n >= max_items:
                    return
            cur = (js.get("pagination") or {}).get("nextCursor")
            if not cur:
                return
            params["cursor"] = cur


# --------------------------------------------------------------------------- #
# Login / scope discovery
# --------------------------------------------------------------------------- #
def login(s1):
    me = s1.get("/web/api/v2.1/user").get("data", {})
    accounts, warn = [], None
    try:
        accounts = [{"id": a["id"], "name": a["name"]}
                    for a in s1.paginate("/web/api/v2.1/accounts", limit=100)]
    except S1Error as e:
        warn = f"Could not list accounts ({e.message}); showing sites only."
    if not accounts:  # site-level token: derive accounts from visible sites
        seen = {}
        try:
            for st in s1.paginate("/web/api/v2.1/sites", limit=100, max_items=500):
                seen[st["accountId"]] = st.get("accountName", st["accountId"])
        except S1Error:
            pass
        accounts = [{"id": k, "name": v} for k, v in seen.items()]
    accounts.sort(key=lambda a: a["name"].lower())
    return {"user": {"email": me.get("email") or me.get("fullName"),
                     "scope": me.get("scope"), "role": me.get("lowestRole")},
            "accounts": accounts, "warning": warn}


def list_sites(s1, account_id=None, q=None, limit=100):
    params = {}
    if account_id:
        params["accountIds"] = account_id
    if q:
        params["query"] = q
    out = []
    for st in s1.paginate("/web/api/v2.1/sites", params, limit=limit, max_items=limit):
        out.append({"id": st["id"], "name": st["name"], "accountId": st.get("accountId"),
                    "accountName": st.get("accountName"), "state": st.get("state")})
    out.sort(key=lambda x: x["name"].lower())
    return out


def list_groups(s1, site_id):
    return [{"id": g["id"], "name": g["name"], "siteId": g.get("siteId"),
             "totalAgents": g.get("totalAgents")}
            for g in s1.paginate("/web/api/v2.1/groups", {"siteIds": site_id}, limit=100)]


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #
def scope_params(scope):
    """Map UI scope -> API filter params. Groups are queried via their site and
    filtered client-side on groupName (the inventory API has no group filter)."""
    t = scope.get("type")
    if t == "account":
        return {"accountIds": scope["id"]}
    if t in ("site", "group"):
        return {"siteIds": scope["siteId"] if t == "group" else scope["id"]}
    raise S1Error("Choose an account, site or group first.", 400)


SUPPORTED_OS = ("WINDOWS", "MACOS")


def norm_os(raw):
    """Console osType -> WINDOWS / MACOS, or '' for anything else (Linux etc. is out of scope)."""
    o = (raw or "").upper()
    if o.startswith("WIN"):
        return "WINDOWS"
    if o.startswith("MAC") or o.startswith("OSX"):
        return "MACOS"
    return ""


def collect_inventory(s1, scope, progress=lambda *a, **k: None, workers=None, cancel=lambda: False):
    workers = workers or int(os.environ.get("INVENTORY_WORKERS", "4"))
    base = scope_params(scope)
    group_name = scope.get("groupName") if scope.get("type") == "group" else None
    progress(stage="Listing applications", done=0, total=0)
    # ask the console for Windows + macOS only; if it rejects/ignores the filter, fall back to client-side filtering
    try:
        apps = list(s1.paginate("/web/api/v2.1/application-management/inventory", dict(base, osTypes="windows,macos")))
        if not apps:
            raise S1Error("empty", 400)
    except S1Error:
        apps = list(s1.paginate("/web/api/v2.1/application-management/inventory", base))
    apps = [a for a in apps if norm_os(a.get("osType")) or not a.get("osType")]
    total, done = len(apps), 0
    progress(stage="Reading install locations", done=0, total=total)
    rows, failed = [], []

    def one(app):
        if cancel():
            raise Cancelled()
        p = dict(base, applicationName=app["applicationName"])
        if app.get("applicationVendor"):
            p["applicationVendor"] = app["applicationVendor"]
        return list(s1.paginate("/web/api/v2.1/application-management/inventory/endpoints", p))

    def add(app, items):
        groups = {}
        for it in items:
            if group_name and it.get("groupName") != group_name:
                continue
            os_ = norm_os(it.get("osType"))
            if not os_:
                continue                     # Linux etc.
            path = (it.get("applicationInstallationPath") or "").strip()
            g = groups.setdefault((path, os_), {"endpoints": set(), "versions": set()})
            g["endpoints"].add(it.get("endpointName") or it.get("endpointId"))
            if it.get("version"):
                g["versions"].add(it["version"])
        for (path, os_), g in groups.items():
            rows.append({"name": app["applicationName"], "publisher": app.get("applicationVendor") or "",
                         "version": ", ".join(sorted(g["versions"])), "os": os_, "install_path": path,
                         "endpoints": len(g["endpoints"]),
                         "endpoint_names": sorted(x for x in g["endpoints"] if x)[:20]})

    def run_pass(todo, nworkers, stage):
        nonlocal done
        retry = []
        ex = ThreadPoolExecutor(max_workers=nworkers)
        try:
            futs = [(a, ex.submit(one, a)) for a in todo]
            for a, f in futs:
                try:
                    add(a, f.result())
                except S1Error:
                    retry.append(a)
                except Cancelled:
                    raise
                done += 1
                progress(stage=stage, done=min(done, total), total=total)
                if cancel():
                    raise Cancelled()
        except Cancelled:
            ex.shutdown(wait=False, cancel_futures=True)
            raise
        ex.shutdown(wait=True)
        return retry

    retry = run_pass(apps, workers, "Reading install locations")
    if retry:       # second chance, gently, after the console has had time to recover
        done = total - len(retry)
        progress(stage=f"Retrying {len(retry)} rate-limited lookups", done=done, total=total)
        time.sleep(5)
        failed = run_pass(retry, max(1, workers // 2), f"Retrying {len(retry)} rate-limited lookups")
    warnings = []
    for a in failed:       # keep the app in the list (without install path/endpoint count) rather than dropping it
        os_ = norm_os(a.get("osType")) or "WINDOWS"
        rows.append({"name": a["applicationName"], "publisher": a.get("applicationVendor") or "", "version": "",
                     "os": os_, "install_path": "", "endpoints": 0, "endpoint_names": []})
    if failed:
        warnings.append(f"{len(failed)} of {total} applications could not be read in detail (the console kept rate-limiting). "
                        "They are listed without an install path, so no hash can be matched. Fetch again later for a complete list.")
    return rows, warnings


# --------------------------------------------------------------------------- #
# Event Search enrichment (hash / signer / process / parent) - from the script
# --------------------------------------------------------------------------- #
def event_search_query(scope):
    clause = (f"account.id='{scope['id']}'" if scope["type"] == "account"
              else f"site.id='{scope['siteId'] if scope['type'] == 'group' else scope['id']}'")
    return (f"event.type='Process Creation' {clause} "
            "| group n=count() by tgt.process.name, tgt.process.image.path, "
            "tgt.process.publisher, tgt.process.signedStatus, "
            "tgt.process.image.sha256, src.process.name | sort -n "
            f"| limit {int(os.environ.get('HASH_QUERY_LIMIT', '10000'))}")


def run_powerquery(s1, query, days=1, deadline_s=180, start=None, end=None):
    end = end or datetime.now(timezone.utc)
    start = start or end - timedelta(days=days)
    iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {"queryType": "PQ", "tenant": True,
            "startTime": iso(start), "endTime": iso(end),
            "pq": {"query": query, "resultType": "TABLE"}}
    js, hdrs = s1.request("POST", "/sdl/v2/api/queries", body=body, bearer=True)
    qid = js.get("id")
    tag = next((v for k, v in hdrs.items() if k.lower() == "x-dataset-query-forward-tag"), None)
    fwd = {"X-Dataset-Query-Forward-Tag": tag} if tag else {}
    end_t = time.time() + deadline_s
    try:
        while True:
            r = s1.request("GET", f"/sdl/v2/api/queries/{qid}",
                           params={"lastStepSeen": 0}, bearer=True, headers=fwd)[0]
            d, t = r.get("stepsCompleted"), r.get("totalSteps", r.get("stepsTotal"))
            if d is not None and t is not None and d >= t:
                break
            if time.time() > end_t:
                raise S1Error("Event Search timed out.", 504)
            time.sleep(1)
        data = r.get("data") or {}
        cols = [c["name"] if isinstance(c, dict) else c for c in data.get("columns", [])]
        return [dict(zip(cols, v)) for v in data.get("values", [])]
    finally:
        try:
            s1.request("DELETE", f"/sdl/v2/api/queries/{qid}", bearer=True, headers=fwd, retries=1)
        except S1Error:
            pass


def run_powerquery_sliced(s1, query, days, progress=lambda **k: None, workers=3, slice_deadline_s=120):
    """Run the query as one-day slices (3 at a time) and merge the counts. A long single
    query over a busy tenant is what used to time out; slices are small and independent."""
    end = datetime.now(timezone.utc)
    windows = [(end - timedelta(days=i + 1), end - timedelta(days=i)) for i in range(days)]
    rows_all, errors, done = [], [], 0
    progress(stage="Searching process telemetry", done=0, total=len(windows))

    def one(w):
        return run_powerquery(s1, query, start=w[0], end=w[1], deadline_s=slice_deadline_s)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for f in [ex.submit(one, w) for w in windows]:
            try:
                rows_all.extend(f.result())
            except S1Error as e:
                errors.append(e)
            done += 1
            progress(stage="Searching process telemetry", done=done, total=len(windows))
    if errors and len(errors) == len(windows):
        raise errors[0]
    merged = {}
    keycols = ["tgt.process.name", "tgt.process.image.path", "tgt.process.publisher",
               "tgt.process.signedStatus", "tgt.process.image.sha256", "src.process.name"]
    for r in rows_all:
        k = tuple(r.get(c) for c in keycols)
        if k in merged:
            merged[k]["n"] = int(merged[k].get("n") or 0) + int(r.get("n") or 0)
        else:
            merged[k] = dict(r)
    return list(merged.values()), len(errors), len(windows)


def _norm(s):
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


_STOP = {"inc", "llc", "ltd", "corporation", "corp", "software", "the", "co", "microsoft",
         "windows", "x64", "x86", "arm64", "64", "bit", "version"}


def _tokens(s):
    return {t for t in _norm(s).split() if len(t) > 2 and t not in _STOP}


def aggregate_binaries(rows):
    agg = {}
    for r in rows:
        key = (r.get("tgt.process.image.path") or "", r.get("tgt.process.image.sha256") or "")
        e = agg.setdefault(key, {"path": key[0], "sha256": key[1],
                                 "process": r.get("tgt.process.name") or "",
                                 "publisher": r.get("tgt.process.publisher") or "",
                                 "signed": r.get("tgt.process.signedStatus") or "",
                                 "parents": defaultdict(int), "count": 0})
        n = int(r.get("n") or 0)
        e["count"] += n
        e["parents"][r.get("src.process.name") or ""] += n
    for e in agg.values():
        e["parent"] = max(e["parents"], key=e["parents"].get) if e["parents"] else ""
    return list(agg.values())


def match_binaries(app, binaries):
    """Binaries that belong to this installed app.

    Strict on purpose: a wrong hash makes a rule target an unrelated binary.
    - Install path known -> only binaries that run from under it (none = no hash).
    - Install path unknown -> fuzzy name/publisher match, but never from the OS
      folders and needing at least 2 name tokens (or the only one) to hit.
    """
    ip = (app.get("install_path") or "").lower().rstrip("\\/")
    if ip:
        return [b for b in binaries if b["path"].lower().startswith(ip)]
    app_pub, app_tok = _norm(app["publisher"]), _tokens(app["name"])
    out = []
    for b in binaries:
        low = b["path"].lower()
        if low.startswith(("c:\\windows\\", "/usr/", "/system/", "/bin/", "/sbin/")):
            continue
        compact = _norm(b["path"]).replace(" ", "")
        pub_n = _norm(b["publisher"])
        hits = sum(1 for t in app_tok if t in compact)
        need = 1 if len(app_tok) <= 1 else 2
        pub_hit = bool(app_pub and pub_n) and (
            app_pub in pub_n or pub_n in app_pub or _tokens(app["publisher"]) & _tokens(b["publisher"]))
        pub_in_path = any(t in compact for t in _tokens(app["publisher"]))
        if hits >= need and (pub_hit or pub_in_path or not pub_n):
            out.append(b)
    return out


def enrich(rows, binaries, max_per_app=5):
    """Expand inventory rows into per-binary rows when Event Search found matches."""
    out = []
    for r in rows:
        ms = sorted(match_binaries(r, binaries), key=lambda b: -b["count"])[:max_per_app]
        if not ms:
            out.append(dict(r, hash="", process="", parent="", signer=""))
            continue
        for m in ms:
            out.append(dict(r, hash=m["sha256"], process=m["process"], parent=m["parent"],
                            signer=m["publisher"] or r["publisher"],
                            publisher=m["publisher"] or r["publisher"],
                            install_path=r["install_path"] or m["path"].rsplit("\\", 1)[0]))
    return out


def finalize_rows(rows):
    """Add stable ids and make sure every row has the enrichment keys."""
    import hashlib
    out = []
    for r in rows:
        r = dict(r)
        for k in ("hash", "process", "parent", "signer"):
            r.setdefault(k, "")
        key = "|".join([r["name"], r["publisher"], r["install_path"], r["hash"], r["process"]]).lower()
        r["id"] = hashlib.sha1(key.encode()).hexdigest()[:12]
        out.append(r)
    out.sort(key=lambda r: (r["name"].lower(), r["install_path"].lower()))
    return out


# --------------------------------------------------------------------------- #
# Rules <-> CSV
# --------------------------------------------------------------------------- #
def rule_key(rule):
    return "|".join((rule.get("Rule Name", ""), rule.get("Path", ""),
                     rule.get("Hash SHA-256", ""))).lower()


def row_to_rule(row, action="ALLOW", name=None):
    """Turn an inventory row into a rule dict using the sample CSV's columns."""
    ver = f" {row['version']}" if row.get("version") else ""
    desc = f"{row['name']}{ver} - {row['endpoints']} endpoint(s)" if row.get("endpoints") else row["name"]
    rule = {c: "" for c in RULE_COLUMNS}
    rule.update({
        "Rule Name": name or row["name"],
        "Description": desc,
        "Rule Action": action.upper() if action.upper() in ACTIONS else "ALLOW",
        "OS Type": row.get("os") or "WINDOWS",
        "Propagation": "true" if action.upper() == "ALLOW" else "false",
        "Publisher": row.get("publisher", ""),
        "Path": row.get("install_path", ""),
        "Binary Identity": "",  # console import rejects populated values (tested)
        "Hash SHA-256": row.get("hash", ""),
        "Process": row.get("process", ""),
        "Parent Process": row.get("parent", ""),
    })
    return rule


ACTIONS = ("ALLOW", "BLOCK", "MONITOR")
TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")


def to_csv_action(action):
    return action if action in ACTIONS else "ALLOW"


def from_csv_action(value):
    v = (value or "").strip().upper()
    return v if v in ACTIONS else "ALLOW"


def clean_rule(rule):
    out = {c: str(rule.get(c, "") if rule.get(c) is not None else "").strip() for c in RULE_COLUMNS}
    out["Rule Action"] = from_csv_action(out["Rule Action"])
    if not out["Rule Name"]:
        raise S1Error("Every rule needs a Rule Name.", 400)
    # Propagation = "allow this app to spawn child processes"; the console rejects it on Block rules.
    out["Propagation"] = ("false" if out["Rule Action"] != "ALLOW" or out["Propagation"].lower() == "false"
                          else "true")
    out["OS Type"] = (out["OS Type"] or "WINDOWS").upper()
    # Binary Identity is a macOS signing identity, e.g. <Type=DevID/ID=com.x.app/Subject=OU:TEAMID>;
    # the console rejects it on Windows rules. macOS "Publisher" must be a 10-char Team ID.
    if out["OS Type"] != "MACOS":
        out["Binary Identity"] = ""
    elif out["Publisher"] and not TEAM_ID.match(out["Publisher"]):
        out["Publisher"] = ""
    if not any(out[k] for k in ("Publisher", "Path", "Binary Identity", "Hash SHA-256", "Process")):
        raise S1Error(f"Rule '{out['Rule Name']}' has nothing to match on (no publisher, path, hash, "
                      "process or binary identity). On macOS, Apple/Mac App Store apps need a Binary Identity.", 400)
    return out
