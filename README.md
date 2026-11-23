# AppControlUI

Web UI (Docker) to turn applications discovered by the SentinelOne agent into Application Control rules.
Until App Control has an API, **Publish writes a CSV** whose columns match `sample-nac-rules.csv`.

## Run
```bash
docker compose up -d --build
open http://localhost:8080
```
Rules are written to `./data/app_control_rules.csv` (plus a timestamped copy in `./data/exports/` on every publish).

Apple Silicon / x64 hosts both work (`python:3.12-slim` is multi-arch).

## Use
1. Sign in with the console URL (e.g. `https://usea1-purple.sentinelone.net`) and a Management API token.
2. Pick **Account**, optionally **Site** (search box filters), optionally **Group**. Scope is whatever your token can see.
3. **Get installed applications** (left). Columns: application, publisher, SHA-256 hash, install directory.
   "Look up hashes" runs an Event Search (process-creation telemetry, last 30 days) to find the hash/process/parent;
   untick it for a faster, inventory-only list.
4. Tick apps (or **Select all** - applies to the filtered list) and press **Add to App Control →**.
   They land in **Planned** as **ALLOW**. Change any row to **BLOCK** (or bulk Set Allow / Set Block), rename, or remove.
   The plan is kept in your browser; nothing is written yet.
5. **Publish** writes the plan to the CSV. Re-publishing a rule with the same name + path + hash updates it
   (e.g. ALLOW → BLOCK) instead of duplicating. **Published rules** can be downloaded, imported from a CSV, or removed.

## Exports, logo and Common applications
- Every **Publish** writes the rules from that action to `data/exports/<site>_<yyyymmddhhmm>.csv` (site name cut to 15 characters,
  non-alphanumerics become `_`; local time of your browser) and shows a banner with a Download button that stays until the next publish.
  All earlier files are listed under **Exported files**. `app_control_rules.csv` stays the cumulative master list.
- Header logo: put the official `logo.svg` (or `logo.png`) in `./brand/` - used in the header and as the browser-tab icon, picked up on refresh, no rebuild.
- **Common applications** (~160 entries, Windows + macOS): whole-vendor publisher/Team-ID rules (all Microsoft, all Adobe, Google,
  Mozilla, Zoom, VMware, Cisco, Dell/HP/NVIDIA/AMD drivers, ...), Apple's system paths, and individual apps. Filter by platform,
  vendor and type. Tags: **in your console** = seen in your own rules export / telemetry; **verify** = public knowledge, check it.
  The list refreshes automatically when you open the page (skipped if it was updated in the last 12 hours, to protect GitHub's rate limit).
  The **Update** button refreshes the ticked rows, or every updatable row currently shown.
  Versions + installer SHA-256: winget (Windows, github.com/microsoft/winget-pkgs; ~60 anonymous GitHub calls/hour - set
  `GITHUB_TOKEN` for more) and Homebrew casks (macOS, formulae.brew.sh; self-updating apps publish no fixed hash). Office, Photoshop etc.
  have no public feed and stay static. Installer hashes are reference only - rules use Publisher + Path + Process.
  Add or fix entries in `catalog.py`.
- Hash lookup now runs one query per day (3 in parallel), so it no longer times out on busy tenants; pick 7/14/30 days.

## Console import quirks (found by testing uploads + a console export)
- Actions: `ALLOW`, `BLOCK`, `MONITOR`. `Propagation` means "allow this app to spawn child processes" - the console
  rejects it on Block, so the app writes `false` for BLOCK/MONITOR (Allow rules get a per-row **Spawn** checkbox).
- `Binary Identity` is a **macOS** signing identity (`<Type=DevID/ID=com.vendor.app/Subject=OU:TEAMID>`,
  `<Type=MAS/ID=...>`, `<Type=Apple/ID=...>`). Windows rules with it are rejected, so it is blanked on Windows.
- macOS `Publisher` is a 10-character **Team ID** (e.g. `UBF8T346G9`); Windows `Publisher` is the signer name
  (e.g. `BRAVE SOFTWARE, INC.`). On macOS the app only keeps a Publisher that looks like a Team ID.
- Apple- and App-Store-signed Mac apps have no Team ID and need a Binary Identity (bundle ID) that the agent telemetry
  does not provide - such rules are rejected with a "nothing to match on" message unless they have a path/hash.
- Path wildcards used in real rules: `*` (one level), `**` (recursive), e.g. `/System/Library/**`.

## Token permissions
Accounts/Sites/Groups view, Application Management (inventory) view; Event Search / Deep Visibility for hashes.

## Notes
- Credentials live in the browser tab's sessionStorage and are sent per request; the server never stores them.
  Inventory jobs keep results (not the token) in memory for 30 minutes.
- The server only talks to hosts ending `.sentinelone.net` (override with `ALLOWED_CONSOLE_SUFFIXES`).
- Behind a TLS-inspecting proxy? Mount your CA bundle and set `REQUESTS_CA_BUNDLE`, or (less safe) `S1_VERIFY_TLS=false`.
- Hash lookup keeps the 10,000 most-executed binaries (`HASH_QUERY_LIMIT`); apps that rarely run may show no hash - their rule is still created from path/publisher.
- Group scope: the inventory API has no group filter, so the group's site is queried and results are filtered by group name.
- The CSV store has no login of its own - compose binds to 127.0.0.1. Put it behind a reverse proxy with auth before exposing it.
- Rule columns beyond the ones we know (all `Exception *` columns) are written blank; edit them in the CSV if needed.

## Develop / test
`pip install -r requirements.txt && python server.py`, then `python tests/test_app.py` (mocked console, no network).
Files: `server.py` (HTTP + CSV store), `s1client.py` (API + inventory + matching, adapted from `s1_app_inventory.py` / `app.py`), `static/` (UI).

## Tuning

If a large account triggers `429` rate-limit messages, lower the parallelism (default 4):

```
INVENTORY_WORKERS=2 docker compose up -d
```

or put `INVENTORY_WORKERS=2` in a `.env` file next to `docker-compose.yml`. The variable goes *before* `docker compose`, not after it.

## Bundled app list (`catalog_seed.csv`)

Besides the curated list in `catalog.py`, the image ships `catalog_seed.csv` - apps harvested from real consoles. Regenerate or extend it from any rules CSV:

```
python3 tools/sanitize_csv.py my_rules.csv            # merges into catalog_seed.csv
python3 tools/sanitize_csv.py my_rules.csv --replace  # rebuild from scratch
```

It generalises `C:\Users\<name>\` to `C:\Users\*\`, collapses duplicates (same app + version + folder), drops temp/build folders and anything the built-in list already covers. Rebuild the image to ship changes. Review the file before committing it - it contains app names, paths and hashes from the source environment. Apps learned at runtime stay separate in `data/learned_apps.json`.
