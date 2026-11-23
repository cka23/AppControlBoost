"""End-to-end test: real server + real HTTP calls, console mocked.
Run:  python3 tests/test_app.py"""
import csv, io, json, os, sys, tempfile, threading, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DATA_DIR"] = tempfile.mkdtemp()
os.environ["PORT"] = "0"
import s1client as c
import catalog
import server

INV = [{"applicationName": "Brave", "applicationVendor": "Brave Software Inc"},
       {"applicationName": "7-Zip", "applicationVendor": "Igor Pavlov"},
       {"applicationName": "NoPath", "applicationVendor": ""}]
EP = {"Brave": [
        {"endpointName": "WIN1", "groupName": "Default Group", "osType": "windows", "version": "1.0",
         "applicationInstallationPath": "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\"},
        {"endpointName": "WIN2", "groupName": "NUC", "osType": "windows", "version": "1.0",
         "applicationInstallationPath": "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\"}],
      "7-Zip": [{"endpointName": "WIN1", "groupName": "Default Group", "osType": "windows", "version": "23",
                 "applicationInstallationPath": "C:\\Program Files\\7-Zip\\"}],
      "NoPath": [{"endpointName": "MAC1", "groupName": "NUC", "osType": "macos", "version": "2"}]}
PQ = [["brave.exe", "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", "Brave Software, Inc.",
       "SIGNED", "a" * 64, "explorer.exe", 50]]
SEEN = []

class Fake(c.S1):
    def request(self, method, path, params=None, body=None, bearer=False, headers=None, retries=4):
        SEEN.append((method, path, dict(params or {})))
        if self.token == "bad":
            raise c.S1Error("Invalid or expired API token.", 401)
        H = {"x-dataset-query-forward-tag": "t"}
        if path == "/web/api/v2.1/user":
            return {"data": {"email": "me@x.com", "scope": "account", "lowestRole": "Admin"}}, H
        if path == "/web/api/v2.1/accounts":
            return {"data": [{"id": "1", "name": "Acme"}], "pagination": {}}, H
        if path == "/web/api/v2.1/sites":
            return {"data": {"sites": [{"id": "9", "name": "HQ", "accountId": "1", "state": "active"}]}, "pagination": {}}, H
        if path == "/web/api/v2.1/groups":
            return {"data": [{"id": "g1", "name": "NUC", "siteId": "9", "totalAgents": 2}], "pagination": {}}, H
        if path == "/web/api/v2.1/application-management/inventory":
            return {"data": INV, "pagination": {}}, H
        if path == "/web/api/v2.1/application-management/inventory/endpoints":
            return {"data": EP[params["applicationName"]], "pagination": {}}, H
        if path == "/sdl/v2/api/queries" and method == "POST":
            return {"id": "q1"}, H
        if path == "/sdl/v2/api/queries/q1" and method == "GET":
            return {"stepsCompleted": 1, "totalSteps": 1, "data": {
                "columns": [{"name": n} for n in ["tgt.process.name", "tgt.process.image.path", "tgt.process.publisher",
                                                  "tgt.process.signedStatus", "tgt.process.image.sha256", "src.process.name", "n"]],
                "values": PQ}}, H
        return {}, H
c.S1 = Fake

srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
B = f"http://127.0.0.1:{port}"
HDR = {"X-S1-URL": "https://usea1-purple.sentinelone.net", "X-S1-Token": "tok"}

def call(path, method="GET", body=None, headers=HDR, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None))
    req = urllib.request.Request(B + path, data=data, method=method, headers=dict(headers, **({"Content-Type": "application/json"} if body is not None else {})))
    try:
        with urllib.request.urlopen(req) as r:
            t = r.read(); return r.status, (json.loads(t) if r.headers["Content-Type"].startswith("application/json") else t.decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def inventory(scope, hashes):
    _, j = call("/api/inventory/start", "POST", {"scope": scope, "hashes": hashes})
    for _ in range(40):
        time.sleep(0.2)
        _, r = call(f"/api/inventory/{j['jobId']}")
        if r["status"] != "running": return r
    raise AssertionError("job hung")

ok = lambda n: print("PASS", n)

# static + health
assert call("/")[0] == 200 and "AppControlUI" in call("/")[1]; ok("index served")
assert call("/../server.py")[0] in (404,) ; ok("no path traversal")
assert call("/api/healthz")[1]["ok"]; ok("healthz")

# login
s, d = call("/api/login", "POST", {})
assert s == 200 and d["accounts"][0]["name"] == "Acme" and d["user"]["email"] == "me@x.com"; ok("login")
assert call("/api/login", "POST", {}, headers={"X-S1-URL": HDR["X-S1-URL"], "X-S1-Token": "bad"})[0] == 401; ok("bad token -> 401")
assert call("/api/login", "POST", {}, headers={"X-S1-URL": "https://evil.example.com", "X-S1-Token": "t"})[0] == 400; ok("non-sentinelone host rejected")
assert call("/api/login", "POST", {}, headers={"X-S1-URL": "http://x.sentinelone.net", "X-S1-Token": "t"})[0] == 400; ok("http rejected")
assert call("/api/sites?accountId=1")[1]["sites"][0]["name"] == "HQ"; ok("sites list")
assert call("/api/groups?siteId=9")[1]["groups"][0]["name"] == "NUC"; ok("groups list")

# inventory: site scope with hashes
SEEN.clear()
r = inventory({"type": "site", "id": "9"}, True)
assert r["status"] == "done", r
rows = {x["name"]: x for x in r["rows"]}
assert rows["Brave"]["hash"] == "a" * 64 and rows["Brave"]["process"] == "brave.exe" and rows["Brave"]["endpoints"] == 2
assert rows["7-Zip"]["hash"] == "" and rows["7-Zip"]["install_path"] == "C:\\Program Files\\7-Zip\\"
assert any(p.get("siteIds") == "9" for _, pa, p in SEEN if "inventory" in pa); ok("site inventory + hash enrichment")

def _inv(scope, hashes, days):
    _, j = call("/api/inventory/start", "POST", {"scope": scope, "hashes": hashes, "days": days})
    for _ in range(60):
        time.sleep(0.2); _, r = call(f"/api/inventory/{j['jobId']}")
        if r["status"] != "running": return r
SEEN.clear(); r3 = _inv({"type": "site", "id": "9"}, True, 3)
assert sum(1 for m, pa, _ in SEEN if pa == "/sdl/v2/api/queries" and m == "POST") == 3; ok("hash lookup runs one query per day")
assert any("3 distinct" not in w and "Hash lookup matched 1 distinct" in w for w in r3["warnings"]); ok("sliced results merged")

# account scope uses accountIds; PQ filtered by account
SEEN.clear(); inventory({"type": "account", "id": "1"}, False)
assert any(p.get("accountIds") == "1" for _, pa, p in SEEN if "inventory" in pa); ok("account scope params")

# group scope: only NUC endpoints, queried via siteIds
SEEN.clear(); r = inventory({"type": "group", "id": "g1", "siteId": "9", "groupName": "NUC"}, False)
names = {x["name"]: x for x in r["rows"]}
assert names["Brave"]["endpoints"] == 1 and "7-Zip" not in names and "NoPath" in names
assert any(p.get("siteIds") == "9" for _, pa, p in SEEN if "inventory" in pa); ok("group scope filtering")
assert call("/api/inventory/start", "POST", {"scope": {}})[0] == 400; ok("scope required")

# rules: publish -> CSV honours sample header
sample = open(os.path.join(os.path.dirname(__file__), "..", "sample-nac-rules.csv")).readline().strip()
assert ",".join(c.RULE_COLUMNS) == sample; # regression: weak single-token match to a System32 binary must not give a hash
sysbin = [{"path": "C:\\Windows\\System32\\StoreDesktopExtension.exe", "sha256": "2" * 64, "process": "StoreDesktopExtension.exe",
           "publisher": "MICROSOFT WINDOWS PUBLISHER", "parent": "RuntimeBroker.exe", "count": 9, "signed": "signed"}]
av1 = {"name": "AV1 Video Extension", "publisher": "Microsoft", "install_path": "C:\\Program Files\\WindowsApps\\Microsoft.AV1VideoExtension_2.0.6.0_arm64__x", "version": "", "endpoints": 1}
assert c.match_binaries(av1, sysbin) == [] and c.match_binaries(dict(av1, install_path=""), sysbin) == []; ok("no false hash match (AV1 regression)")
# macOS / action rules learned from the console export
assert c.clean_rule({"Rule Name": "m", "Rule Action": "MONITOR", "Path": "/x", "Propagation": "true"})["Propagation"] == "false"
assert c.clean_rule({"Rule Name": "w", "OS Type": "WINDOWS", "Binary Identity": "<Type=MAS/ID=x>", "Path": "C:\\a"})["Binary Identity"] == ""
mac = c.clean_rule({"Rule Name": "mac", "OS Type": "MACOS", "Publisher": "Mozilla", "Binary Identity": "<Type=Apple/ID=com.apple.Chess>"})
assert mac["Publisher"] == "" and mac["Binary Identity"].startswith("<Type=Apple")
assert c.clean_rule({"Rule Name": "mac2", "OS Type": "MACOS", "Publisher": "43AQ936H96"})["Publisher"] == "43AQ936H96"
try: c.clean_rule({"Rule Name": "empty", "OS Type": "MACOS", "Publisher": "Mozilla"}); raise SystemExit("should fail")
except c.S1Error: pass
ok("action/macOS rules")
# ---- catalog (GitHub mocked) ----
class R:
    def __init__(s, code=200, js=None, text=""): s.status_code, s._js, s.text = code, js, text
    def json(s): return s._js
    def raise_for_status(s):
        if s.status_code >= 400: raise RuntimeError(f"http {s.status_code}")
YAML = """Installers:
- Architecture: x86
  InstallerType: exe
  InstallerUrl: https://x/32.exe
  InstallerSha256: %s
- Architecture: x64
  InstallerType: exe
  InstallerUrl: https://x/64.exe
  InstallerSha256: %s
""" % ("1" * 64, "ab" * 32)
def fake_get(url, **kw):
    if "Notepad%2B%2B" in url or "Notepad++" in url:
        return R(404, text="nf")
    if "git/trees" in url:
        return R(200, {"tree": [{"path": p, "type": "tree"} for p in ["99.0", "160.0", "135.0.1", "beta", "9.1"]]})
    if "raw.githubusercontent" in url:
        return R(200, text=YAML) if "/160.0/" in url else R(404, text="")
    return R(500)
CALLS = []
CASK = {"version": "158.0.1,9999", "sha256": "no_check", "url": "https://dl/x.dmg"}
def fake_get2(url, **kw):
    CALLS.append(url)
    if "formulae.brew.sh" in url:
        if "claude" in url: return R(200, dict(CASK, sha256="cd" * 32, version="1.2.3"))
        return R(404, text="nf") if "nope" in url else R(200, CASK)
    return fake_get(url, **kw)
catalog.requests.get = fake_get2

# nothing is fetched just by loading the catalog (no auto-update)
CALLS.clear()
cat0 = call("/api/catalog")[1]
assert CALLS == [] and cat0["updatedAt"] == "" and cat0["ageHours"] is None and len([x for x in cat0["apps"] if x["trust"] != "learned"]) == len(catalog.SEED); ok("catalog load does not touch the internet")
assert len(catalog.SEED) > 100 and {a["os"] for a in cat0["apps"]} == {"WINDOWS", "MACOS"}; ok("comprehensive list (Windows + macOS)")
assert any(a["kind"] == "vendor" and a["publisher"] == "MICROSOFT CORPORATION" for a in cat0["apps"])
assert any(a["kind"] == "vendor" and a["publisher"] == "JQ525L2MZD" for a in cat0["apps"]); ok("whole-vendor entries (Microsoft, Adobe)")

# every catalog entry turns into a valid, importable-shaped rule
for a in [x for x in cat0["apps"] if x["trust"] != "learned"]:
    row = {"name": a["name"], "publisher": a["publisher"], "install_path": a["install_path"], "process": a["process"],
           "os": a["os"], "version": "", "endpoints": 0}
    rule = c.clean_rule(c.row_to_rule(row))
    assert rule["Binary Identity"] == "" and rule["OS Type"] == a["os"], a["name"]
    if a["os"] == "MACOS" and a["publisher"]: assert c.TEAM_ID.match(rule["Publisher"]), a["name"]
ok("all catalog entries produce valid rules")

# update only selected ids; winget + brew sources; static entries skipped
ids = {"common-chrome", "common-m-claude", "common-m-chrome", "common-o-word", "common-notepadpp"}
CALLS.clear()
apps, n, limited = catalog.update_all(os.environ["DATA_DIR"], ids)
by = {a["id"]: a for a in apps}
assert n == 4 and not limited, n          # Word has no source -> not counted
assert all("api.github" in u or "raw.github" in u or "brew.sh" in u for u in CALLS) and len(CALLS) < 12; ok("update touches only selected entries")
assert by["common-chrome"]["version"] == "160.0" and by["common-chrome"]["installer_sha256"] == "AB" * 32 and by["common-chrome"]["status"] == "ok"
assert by["common-m-claude"]["version"] == "1.2.3" and by["common-m-claude"]["installer_sha256"] == "CD" * 32
assert by["common-m-chrome"]["version"] == "158.0.1" and by["common-m-chrome"]["installer_sha256"] == "" and by["common-m-chrome"]["status"] == "ok"
assert by["common-notepadpp"]["status"] == "update failed" and "not found" in by["common-notepadpp"]["error"]
assert by["common-o-word"]["status"] == "static" and by["common-firefox"]["version"] == ""; ok("winget + Homebrew update, failures isolated, others untouched")

# rate limit: remaining GitHub lookups are skipped, brew still works
def limited_get(url, **kw):
    if "api.github" in url: return R(403, text="API rate limit exceeded")
    return fake_get2(url, **kw)
catalog.requests.get = limited_get
apps, n, limited = catalog.update_all(os.environ["DATA_DIR"], {"common-firefox", "common-zoom", "common-m-claude"}, workers=1)
by = {a["id"]: a for a in apps}
assert limited and by["common-zoom"]["status"] == "update failed" and by["common-m-claude"]["status"] == "ok"; ok("rate limit detected and reported")
catalog.requests.get = fake_get2

# API job with ids
_, j = call("/api/catalog/update", "POST", {"ids": ["common-m-claude"]})
for _ in range(50):
    time.sleep(0.2); _, r = call(f"/api/inventory/{j['jobId']}")
    if r["status"] != "running": break
assert r["status"] == "done" and any("Updated 1 of 1" in w for w in r["warnings"]) and len([x for x in r["rows"] if x["trust"] != "learned"]) == len(catalog.SEED); ok("catalog update job via API (selected only)")
cj = call("/api/catalog")[1]
assert cj["updatedAt"] and cj["ageHours"] is not None and 0 <= cj["ageHours"] < 0.1; ok("catalog served from cache with age")
ok("columns match sample-nac-rules.csv header")
b = rows["Brave"]
rule = c.row_to_rule(b); rule2 = c.row_to_rule(rows["7-Zip"], "BLOCK")
s, d = call("/api/rules/publish", "POST", {"rules": [rule, rule2], "siteName": "Sanjay K", "stamp": "202612191026"})
assert d["added"] == 2 and d["total"] == 2; ok("publish adds")
assert d["export"] == "Sanjay_K_202612191026.csv", d; ok("export file named <site>_<yyyymmddhhmm>.csv")
assert server.export_name("A Very Long Site Name Here", "202612191026") == "A_Very_Long_Sit_202612191026.csv"; ok("site name limited to 15 chars")
assert server.export_name("", "bogus").endswith(".csv") and server.export_name("!!!", "202612191026").startswith("rules_"); ok("name fallbacks")
ex = call("/api/rules/exports")[1]["exports"]
assert ex[0]["name"] == "Sanjay_K_202612191026.csv" and ex[0]["rules"] == 2; ok("exports listed")
st, body = call("/api/rules/exports/Sanjay_K_202612191026.csv")
assert st == 200 and body.splitlines()[0] == ",".join(c.RULE_COLUMNS) and len(body.strip().splitlines()) == 3; ok("export downloadable (batch only)")
assert call("/api/rules/exports/..%2Fserver.py")[0] == 404 and call("/api/rules/exports/nope.csv")[0] == 404; ok("export path safe")
rule["Rule Action"] = "BLOCK"
d = call("/api/rules/publish", "POST", {"rules": [rule]})[1]
assert d["added"] == 0 and d["updated"] == 1 and d["total"] == 2; ok("republish updates, no duplicate")
txt = call("/api/rules/download")[1]
rd = list(csv.DictReader(io.StringIO(txt)))
assert txt.splitlines()[0] == sample and rd[0]["Rule Action"] == "BLOCK" and rd[1]["Rule Action"] == "BLOCK"
assert rd[0]["Binary Identity"] == "" and rd[0]["Propagation"] == "false" and rd[1]["Propagation"] == "false"
assert rd[0]["Hash SHA-256"] == "a" * 64 and rd[0]["OS Type"] == "WINDOWS"; ok("CSV content")
assert call("/api/rules/publish", "POST", {"rules": []})[0] == 400; ok("empty publish rejected")
assert call("/api/rules/publish", "POST", {"rules": [{"Rule Name": ""}]})[0] == 400; ok("nameless rule rejected")
assert len(os.listdir(os.path.join(os.environ["DATA_DIR"], "exports"))) >= 2; ok("timestamped export copies")

# import sample CSV, delete
d = call("/api/rules/import", "POST", raw=open(os.path.join(os.path.dirname(__file__), "..", "sample-nac-rules.csv"), "rb").read(),
         headers=dict(HDR, **{"Content-Type": "text/csv"}))[1]
assert d["added"] == 1 and d["total"] == 3; ok("import sample CSV")
k = c.rule_key(c.clean_rule(c.row_to_rule(rows["7-Zip"])))
call("/api/rules/delete", "POST", {"keys": [k]})
assert len(call("/api/rules")[1]["rules"]) == 2; ok("delete")

# ---- learned applications
lc = call("/api/catalog")[1]
L = [a for a in lc["apps"] if a["trust"] == "learned"]
assert L and lc["learned"] == len(L); ok("inventory fetches are learned into the Common list")
assert all(a["id"].startswith("learned-") and a["status"] == "learned" and not a["updatable"] and a["seen_count"] >= 1 for a in L); ok("learned entry shape")
sevenzip = [a for a in L if a["name"] == "Brave" and a["hash"]]
assert sevenzip and sevenzip[0]["os"] == "WINDOWS" and sevenzip[0]["hash"]; ok("learned entry keeps observed hash + path")
n0 = len(L)
new, upd = catalog.learn(os.environ["DATA_DIR"], [{"name": "Brave", "publisher": sevenzip[0]["publisher"], "install_path": sevenzip[0]["install_path"], "version": "99.9", "hash": "b" * 64}], "Test")
L2 = [a for a in call("/api/catalog")[1]["apps"] if a["trust"] == "learned"]
s2 = [a for a in L2 if a["id"] == sevenzip[0]["id"]][0]
assert (new, upd) == (0, 1) and len(L2) == n0 and s2["version"] == "99.9" and s2["hash"] == "b" * 64 and s2["seen_count"] == sevenzip[0]["seen_count"] + 1 and "Test" in s2["seen_in"]; ok("re-learning updates in place, no duplicates")
assert catalog.learn(os.environ["DATA_DIR"], [{"name": "", "publisher": "x"}]) == (0, 0); ok("nameless rows ignored")
assert catalog.learn(os.environ["DATA_DIR"], [{"name": "Mac Thing", "install_path": "/Applications/Mac Thing.app", "publisher": "ABCDE12345"}])[0] == 1
assert [a for a in call("/api/catalog")[1]["apps"] if a["name"] == "Mac Thing"][0]["os"] == "MACOS"; ok("OS inferred from path")
rm = call("/api/catalog/forget", "POST", {"ids": [s2["id"]]})[1]["removed"]
assert rm == 1 and not [a for a in call("/api/catalog")[1]["apps"] if a["id"] == s2["id"]]; ok("forget selected")
assert call("/api/catalog/forget", "POST", {})[0] == 400; ok("forget needs ids or all")
call("/api/catalog/forget", "POST", {"all": True})
lc = call("/api/catalog")[1]
assert lc["learned"] == 0 and len(lc["apps"]) == len(catalog.SEED); ok("forget all leaves built-in list intact")

# ---- Linux excluded, rate limits never drop apps, retry-after honoured, cancel
class FakeS1:
    def __init__(self, flaky=()):
        self.flaky, self.calls = set(flaky), {}
    def paginate(self, path, params=None, **kw):
        if path.endswith("/inventory"):
            yield {"applicationName": "Chrome", "applicationVendor": "Google", "osType": "windows"}
            yield {"applicationName": "Safari", "applicationVendor": "Apple", "osType": "macos"}
            yield {"applicationName": "bash-thing", "applicationVendor": "GNU", "osType": "linux"}
            yield {"applicationName": "Flaky", "applicationVendor": "X", "osType": "windows"}
            return
        n = params["applicationName"]; self.calls[n] = self.calls.get(n, 0) + 1
        if n in self.flaky and self.calls[n] <= self.flaky_fails:
            raise c.S1Error("429 on /x.", 429)
        yield {"osType": "windows" if n != "Safari" else "macos", "applicationInstallationPath": "C:\\" + n, "endpointName": "e1", "version": "1"}
        yield {"osType": "linux", "applicationInstallationPath": "/usr/bin/" + n, "endpointName": "e2", "version": "1"}
f = FakeS1(flaky={"Flaky"}); f.flaky_fails = 1
c.time.sleep = lambda *_: None
rows_, warns_ = c.collect_inventory(f, {"type": "account", "id": "1"})
names = {(r["name"], r["os"]) for r in rows_}
assert ("bash-thing", "LINUX") not in names and not any(r["os"] not in ("WINDOWS", "MACOS") for r in rows_) and not any(r["name"] == "bash-thing" for r in rows_) and not any(r["install_path"].startswith("/usr") for r in rows_); ok("Linux apps and Linux installs excluded")
assert ("Safari", "MACOS") in names and ("Flaky", "WINDOWS") in names and not warns_; ok("a rate-limited lookup is retried and recovered")
f = FakeS1(flaky={"Flaky"}); f.flaky_fails = 99
rows_, warns_ = c.collect_inventory(f, {"type": "account", "id": "1"})
fl = [r for r in rows_ if r["name"] == "Flaky"]
assert fl and fl[0]["install_path"] == "" and len(warns_) == 1 and "1 of 3 applications" in warns_[0]; ok("persistent failures keep the app and give ONE summary warning")
try:
    c.collect_inventory(FakeS1(), {"type": "account", "id": "1"}, cancel=lambda: True); assert False
except c.Cancelled:
    ok("cancel stops collection")

class R429:
    status_code = 429; headers = {"Retry-After": "3"}
s1o = c.S1("https://x.sentinelone.net", "t")
c.time.time = lambda: 1000.0
s1o._backoff(R429(), 0)
assert 1003 <= s1o._pause_until <= 1004.01; ok("Retry-After honoured and shared across workers")
print("ALL TESTS PASSED")
