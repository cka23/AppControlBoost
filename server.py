"""AppControlUI - web server (Python stdlib http.server + requests).

Stateless w.r.t. credentials: the browser keeps the console URL + API token in
sessionStorage and sends them per request (X-S1-URL / X-S1-Token headers).
The server only keeps (a) in-memory inventory jobs, which hold results but not
the token, and (b) the rules CSV in DATA_DIR - the stand-in for App Control.
"""
import calendar
import csv
import io
import json
import logging
import mimetypes
import os
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import catalog
import s1client as c

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("appcontrolui")

ROOT = Path(__file__).parent
STATIC = ROOT / "static"
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))
RULES_FILE = DATA_DIR / os.environ.get("RULES_FILENAME", "app_control_rules.csv")
VERIFY_TLS = os.environ.get("S1_VERIFY_TLS", "true").lower() not in ("0", "false", "no")
ALLOWED = tuple(s.strip() for s in os.environ.get(
    "ALLOWED_CONSOLE_SUFFIXES", ".sentinelone.net").split(",") if s.strip())
PORT = int(os.environ.get("PORT", "8080"))
MAX_BODY = 20 * 1024 * 1024

JOBS, JOBS_LOCK = {}, threading.Lock()
FILE_LOCK = threading.Lock()


# ----------------------------- rules CSV store ----------------------------- #
def read_rules():
    if not RULES_FILE.exists():
        return []
    with open(RULES_FILE, newline="", encoding="utf-8-sig") as f:
        out = [{col: (row.get(col) or "").strip() for col in c.RULE_COLUMNS}
               for row in csv.DictReader(f)]
    for r in out:
        r["Rule Action"] = c.from_csv_action(r["Rule Action"])
    return out


def render_csv(rules):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=c.RULE_COLUMNS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    w.writerows([dict(r, **{"Rule Action": c.to_csv_action(r.get("Rule Action"))}) for r in rules])
    return buf.getvalue()


def write_rules(rules):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = RULES_FILE.with_suffix(".tmp")
    tmp.write_text(render_csv(rules), encoding="utf-8")
    os.replace(tmp, RULES_FILE)



def export_name(site_name, stamp):
    """<site, max 15 chars>_<yyyymmddhhmm>.csv  e.g. 'Sanjay K' -> sanjay_K_202612191026.csv"""
    base = re.sub(r"[^A-Za-z0-9]+", "_", site_name or "").strip("_")[:15].strip("_") or "rules"
    if not re.fullmatch(r"\d{12}", stamp or ""):
        stamp = time.strftime("%Y%m%d%H%M")
    return f"{base}_{stamp}.csv"


def publish(new_rules, site_name="", stamp=""):
    """Append rules to the master CSV (rules with the same name+path+hash are updated in place) and
    write exactly the rules published in this action to a named export file for upload to the console."""
    with FILE_LOCK:
        existing = read_rules()
        index = {c.rule_key(r): i for i, r in enumerate(existing)}
        added = updated = 0
        batch = []
        for raw in new_rules:
            r = c.clean_rule(raw)
            batch.append(r)
            k = c.rule_key(r)
            if k in index:
                existing[index[k]] = r; updated += 1
            else:
                index[k] = len(existing); existing.append(r); added += 1
        write_rules(existing)
        export_dir = DATA_DIR / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        name = export_name(site_name, stamp)
        n = 2
        while (export_dir / name).exists():
            name = export_name(site_name, stamp).replace(".csv", f"_{n}.csv"); n += 1
        (export_dir / name).write_text(render_csv(batch), encoding="utf-8")
        return {"added": added, "updated": updated, "total": len(existing), "export": name}


def list_exports():
    d = DATA_DIR / "exports"
    if not d.is_dir():
        return []
    files = sorted((f for f in d.glob("*.csv")), key=lambda f: f.stat().st_mtime, reverse=True)
    return [{"name": f.name, "size": f.stat().st_size,
             "rules": max(0, sum(1 for _ in open(f, encoding="utf-8")) - 1),
             "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(f.stat().st_mtime))} for f in files[:50]]


# ------------------------------ inventory jobs ----------------------------- #
def run_job(job_id, s1, scope, do_enrich, days):
    job = JOBS[job_id]

    def progress(**kw):
        job["progress"].update(kw)

    try:
        rows, warnings = c.collect_inventory(s1, scope, progress, cancel=lambda: job.get("cancel", False))
        job["warnings"].extend(warnings)
        if do_enrich and rows:
            try:
                q = c.event_search_query(scope)
                res, failed, total = c.run_powerquery_sliced(s1, q, days, progress)
                bins = c.aggregate_binaries(res)
                rows = c.enrich(rows, bins)
                msg = f"Hash lookup matched {len(bins)} distinct binaries (last {days} days)."
                if failed:
                    msg += f" {failed} of {total} daily searches timed out, so hashes may be incomplete."
                job["warnings"].append(msg)
            except c.S1Error as e:
                why = ("The token needs Event Search / Deep Visibility access." if e.status in (401, 403)
                       else "Try a shorter lookback or a smaller scope.")
                job["warnings"].append(f"Hash lookup failed ({e.message}); showing inventory fields only. {why}")
        job["rows"] = c.finalize_rows(rows)
        try:   # remember what this scope reported so the Common list grows with your own estate
            n_new, n_upd = catalog.learn(DATA_DIR, job["rows"], scope.get("siteName", ""))
            job["learned"] = {"new": n_new, "updated": n_upd}
        except Exception:  # noqa - learning must never break an inventory fetch
            log.exception("learn failed")
        job["status"] = "done"
    except c.Cancelled:
        job["status"] = "cancelled"
    except c.S1Error as e:
        job["status"], job["error"] = "error", e.message
    except Exception as e:  # noqa
        log.exception("inventory job failed")
        job["status"], job["error"] = "error", f"Unexpected error: {e}"
    finally:
        job["finished"] = time.time()
        s1.session.close()
        # job holds results only; the token lived in the S1 object and is dropped here


def run_catalog_job(job_id, ids=None):
    job = JOBS[job_id]
    try:
        apps, n, limited = catalog.update_all(DATA_DIR, ids, lambda **kw: job["progress"].update(kw))
        failed = [a["name"] for a in apps if a["status"] == "update failed" and (not ids or a["id"] in ids)]
        job["warnings"].append(f"Updated {n - len(failed)} of {n} application(s).")
        if limited:
            job["warnings"].append("GitHub rate limit reached - set GITHUB_TOKEN or update fewer apps at a time.")
        elif failed:
            job["warnings"].append("Could not update: " + ", ".join(failed[:8]) + (" ..." if len(failed) > 8 else "") + " (previous values kept; hover the red tag for the reason).")
        job["rows"], job["status"] = apps + catalog.load_learned(DATA_DIR), "done"
    except Exception as e:  # noqa
        log.exception("catalog update failed")
        job["status"], job["error"] = "error", f"Update failed: {e}"
    finally:
        job["finished"] = time.time()


def reap_jobs():
    with JOBS_LOCK:
        for k in [k for k, j in JOBS.items() if j.get("finished") and time.time() - j["finished"] > 1800]:
            del JOBS[k]


# --------------------------------- handler --------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "AppControlUI"

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    # helpers
    def send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise c.S1Error("Request too large.", 413)
        return self.rfile.read(n) if n else b""

    def read_json(self):
        raw = self.read_body()
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            raise c.S1Error("Invalid JSON body.", 400)

    def client(self, body=None):
        url = self.headers.get("X-S1-URL") or (body or {}).get("url")
        tok = self.headers.get("X-S1-Token") or (body or {}).get("token")
        if not tok:
            raise c.S1Error("Not signed in.", 401)
        return c.S1(c.normalize_base_url(url, ALLOWED), tok.strip(), VERIFY_TLS)

    # routing
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        u = urlparse(self.path)
        path, q = u.path, {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if method == "GET" and not path.startswith("/api/"):
                return self.static(path)
            if method == "GET" and path == "/api/healthz":
                return self.send_json({"ok": True})
            if method == "POST" and path == "/api/login":
                body = self.read_json()
                s1 = self.client(body)
                return self.send_json(c.login(s1))
            if method == "GET" and path == "/api/sites":
                return self.send_json({"sites": c.list_sites(
                    self.client(), q.get("accountId"), q.get("q"))})
            if method == "GET" and path == "/api/groups":
                if not q.get("siteId"):
                    raise c.S1Error("siteId is required.", 400)
                return self.send_json({"groups": c.list_groups(self.client(), q["siteId"])})
            if method == "POST" and path == "/api/inventory/start":
                body = self.read_json()
                s1 = self.client()
                scope = body.get("scope") or {}
                c.scope_params(scope)  # validates
                reap_jobs()
                jid = uuid.uuid4().hex
                days = max(1, min(int(body.get("days") or 7), 30))
                JOBS[jid] = {"status": "running", "progress": {"stage": "Starting", "done": 0, "total": 0},
                             "warnings": [], "created": time.time()}
                threading.Thread(target=run_job, daemon=True,
                                 args=(jid, s1, scope, bool(body.get("hashes")), days)).start()
                return self.send_json({"jobId": jid})
            m = re.fullmatch(r"/api/inventory/([0-9a-f]{32})/cancel", path)
            if method == "POST" and m:
                job = JOBS.get(m.group(1))
                if job:
                    job["cancel"] = True
                return self.send_json({"ok": True})
            m = re.fullmatch(r"/api/inventory/([0-9a-f]{32})", path)
            if method == "GET" and m:
                job = JOBS.get(m.group(1))
                if not job:
                    raise c.S1Error("Unknown or expired job.", 404)
                out = {k: job.get(k) for k in ("status", "progress", "warnings", "error", "learned")}
                if job["status"] == "done":
                    out["rows"] = job["rows"]
                return self.send_json(out)
            if method == "GET" and path == "/api/rules":
                return self.send_json({"columns": c.RULE_COLUMNS, "rules": read_rules(),
                                       "file": RULES_FILE.name})
            if method == "POST" and path == "/api/rules/publish":
                body = self.read_json()
                rules = body.get("rules") or []
                if not rules:
                    raise c.S1Error("Nothing to publish.", 400)
                res = publish(rules, str(body.get("siteName") or ""), str(body.get("stamp") or ""))
                res["file"] = RULES_FILE.name
                return self.send_json(res)
            if method == "POST" and path == "/api/rules/delete":
                keys = set((self.read_json().get("keys")) or [])
                with FILE_LOCK:
                    rules = read_rules()
                    kept = [r for r in rules if c.rule_key(r) not in keys]
                    write_rules(kept)
                return self.send_json({"removed": len(rules) - len(kept), "total": len(kept)})
            if method == "POST" and path == "/api/rules/import":
                text = self.read_body().decode("utf-8-sig", errors="replace")
                rdr = csv.DictReader(io.StringIO(text))
                if not rdr.fieldnames or "Rule Name" not in rdr.fieldnames:
                    raise c.S1Error("That CSV has no 'Rule Name' column.", 400)
                rules = [c.clean_rule(r) for r in rdr if (r.get("Rule Name") or "").strip()]
                res = publish(rules)
                return self.send_json(res)
            if method == "GET" and path == "/api/rules/exports":
                return self.send_json({"exports": list_exports()})
            m = re.fullmatch(r"/api/rules/exports/([A-Za-z0-9_\-]+(?:_\d+)?\.csv)", path)
            if method == "GET" and m:
                f = DATA_DIR / "exports" / m.group(1)
                if not f.is_file():
                    raise c.S1Error("Export not found.", 404)
                return self.send_file(f.read_bytes(), f.name)
            if method == "GET" and path == "/api/catalog":
                apps = catalog.load(DATA_DIR)
                learned = catalog.load_learned(DATA_DIR)
                ts = [a["updated_at"] for a in apps if a["updated_at"]]
                age = None
                if ts:
                    try:
                        age = (time.time() - calendar.timegm(time.strptime(max(ts)[:19], "%Y-%m-%d %H:%M:%S"))) / 3600
                    except ValueError:
                        pass
                return self.send_json({"apps": apps + learned, "learned": len(learned), "updatedAt": max(ts) if ts else "", "ageHours": age})
            if method == "POST" and path == "/api/catalog/forget":
                body = self.read_json()
                ids = {str(i) for i in (body.get("ids") or [])}
                if not ids and not body.get("all"):
                    raise c.S1Error("Nothing to forget.", 400)
                return self.send_json({"removed": catalog.forget(DATA_DIR, None if body.get("all") else ids)})
            if method == "POST" and path == "/api/catalog/update":
                body = self.read_json()
                ids = {str(i) for i in (body.get("ids") or [])} or None
                reap_jobs()
                jid = uuid.uuid4().hex
                JOBS[jid] = {"status": "running", "progress": {"stage": "Starting", "done": 0, "total": 0},
                             "warnings": [], "created": time.time()}
                threading.Thread(target=run_catalog_job, args=(jid, ids), daemon=True).start()
                return self.send_json({"jobId": jid})
            if method == "GET" and path == "/api/rules/download":
                data = render_csv(read_rules()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{RULES_FILE.name}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            raise c.S1Error("Not found.", 404)
        except c.S1Error as e:
            self.send_json({"error": e.message}, e.status)
        except Exception as e:  # noqa
            log.exception("unhandled")
            self.send_json({"error": f"Server error: {e}"}, 500)

    def send_file(self, data, filename):
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def static(self, path):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        f = (STATIC / rel).resolve()
        if STATIC.resolve() not in f.parents or not f.is_file():
            self.send_response(404); self.end_headers(); return
        data = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(f.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        probe = DATA_DIR / ".write_test"
        probe.write_text("ok"); probe.unlink()
    except OSError as e:
        log.error("DATA_DIR %s is not writable (%s). The UI will start, but Publish will fail "
                  "until the folder is writable by the container user.", DATA_DIR, e)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log.info("AppControlUI listening on :%s (rules file: %s, tls verify: %s)", PORT, RULES_FILE, VERIFY_TLS)
    srv.serve_forever()


if __name__ == "__main__":
    main()
