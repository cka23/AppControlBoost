"""Common Applications catalog.

Static seed (name, signer, typical install folder, main process) + live "Update" that asks the public
winget package repository (github.com/microsoft/winget-pkgs) for the latest version and the installer's
SHA-256. NOTE: that hash is of the *installer* file, not of the installed executables, so it is shown for
reference and is not written into rules (rules from this list use Publisher + Path + Process).
"""
import hashlib
import json
import os
import threading
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import requests

TIMEOUT = 25
HEADERS = {"User-Agent": "AppControlUI", "Accept": "application/vnd.github+json"}
if os.environ.get("GITHUB_TOKEN"):
    HEADERS["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]

# ---------------------------------------------------------------------------------------------------
# Catalog data.  trust: "export" = value seen in your own console (rules export / process telemetry);
#                       "verify" = public knowledge - confirm against your own apps before relying on it.
# ---------------------------------------------------------------------------------------------------
_E, _V = "export", "verify"
SEED = []


def _add(key, name, vendor, os_, pub, path="", proc="", src=None, trust=_V, kind="app"):
    SEED.append({"key": key, "name": name, "vendor": vendor, "os": os_, "publisher": pub, "install_path": path,
                 "process": proc, "source": src, "trust": trust, "kind": kind})


def win(key, name, vendor, pub, path, proc, winget=None, trust=_V):
    _add(key, name, vendor, "WINDOWS", pub, path, proc, ("winget", winget) if winget else None, trust)


def mac(key, name, vendor, team, app, proc, cask=None, trust=_V):
    _add(key, name, vendor, "MACOS", team, f"/Applications/{app}.app/**", proc, ("brew", cask) if cask else None, trust)


def vendor_win(key, name, vendor, pub, trust=_V):
    _add(key, name, vendor, "WINDOWS", pub, kind="vendor", trust=trust)


def vendor_mac(key, name, vendor, team, trust=_V):
    _add(key, name, vendor, "MACOS", team, kind="vendor", trust=trust)


def path_mac(key, name, glob):
    _add(key, name, "Apple (macOS system)", "MACOS", "", glob, kind="vendor", trust=_E)


PF, PF86 = "C:\\Program Files\\", "C:\\Program Files (x86)\\"
OFF = PF + "Microsoft Office\\root\\Office16\\"

# ---- original 15 (kept) ----
win("chrome", "Google Chrome", "Google", "GOOGLE LLC", PF + "Google\\Chrome\\Application\\", "chrome.exe", "Google.Chrome", _E)
win("firefox", "Mozilla Firefox", "Mozilla", "MOZILLA CORPORATION", PF + "Mozilla Firefox\\", "firefox.exe", "Mozilla.Firefox", _E)
win("edge", "Microsoft Edge", "Microsoft", "MICROSOFT CORPORATION", PF86 + "Microsoft\\Edge\\Application\\", "msedge.exe", "Microsoft.Edge", _E)
win("brave", "Brave", "Brave", "BRAVE SOFTWARE, INC.", PF + "BraveSoftware\\Brave-Browser\\Application\\", "brave.exe", "Brave.Brave", _E)
win("acrobat", "Adobe Acrobat Reader", "Adobe", "ADOBE INC.", PF + "Adobe\\Acrobat DC\\Acrobat\\", "Acrobat.exe", "Adobe.Acrobat.Reader.64-bit", _E)
win("zoom", "Zoom Workplace", "Zoom", "ZOOM COMMUNICATIONS, INC.", PF + "Zoom\\bin\\", "Zoom.exe", "Zoom.Zoom", _E)
win("vscode", "Visual Studio Code", "Microsoft", "MICROSOFT CORPORATION", PF + "Microsoft VS Code\\", "Code.exe", "Microsoft.VisualStudioCode", _E)
win("notepadpp", "Notepad++", "Notepad++", "NOTEPAD++", PF + "Notepad++\\", "notepad++.exe", "Notepad++.Notepad++", _E)
win("7zip", "7-Zip", "7-Zip", "IGOR PAVLOV", PF + "7-Zip\\", "7zFM.exe", "7zip.7zip")
win("vlc", "VLC media player", "VideoLAN", "VIDEOLAN", PF + "VideoLAN\\VLC\\", "vlc.exe", "VideoLAN.VLC")
win("wireshark", "Wireshark", "Wireshark", "WIRESHARK FOUNDATION", PF + "Wireshark\\", "Wireshark.exe", "WiresharkFoundation.Wireshark", _E)
win("putty", "PuTTY", "PuTTY", "SIMON TATHAM", PF + "PuTTY\\", "putty.exe", "PuTTY.PuTTY")
win("dropbox", "Dropbox", "Dropbox", "DROPBOX, INC.", PF86 + "Dropbox\\Client\\", "Dropbox.exe", "Dropbox.Dropbox")
win("teamviewer", "TeamViewer", "TeamViewer", "TEAMVIEWER GERMANY GMBH", PF + "TeamViewer\\", "TeamViewer.exe", "TeamViewer.TeamViewer")
win("discord", "Discord (per-user install)", "Discord", "DISCORD INC.", "", "Discord.exe", "Discord.Discord", _E)

# ---- Windows: whole-vendor publisher rules (one rule covers everything that vendor signs) ----
for k, n, v, p, t in [
    ("v-ms", "All Microsoft apps (Windows)", "Microsoft", "MICROSOFT CORPORATION", _E),
    ("v-mswin", "Microsoft Windows components", "Microsoft", "MICROSOFT WINDOWS", _E),
    ("v-mswinpub", "Microsoft Windows Publisher", "Microsoft", "MICROSOFT WINDOWS PUBLISHER", _E),
    ("v-msdyn", "Microsoft Dynamic Code Publisher (.NET)", "Microsoft", "MICROSOFT DYNAMIC CODE PUBLISHER", _E),
    ("v-mshw", "Microsoft Windows Hardware Compatibility (drivers)", "Microsoft", "MICROSOFT WINDOWS HARDWARE COMPATIBILITY PUBLISHER", _E),
    ("v-adobe", "All Adobe apps (Windows)", "Adobe", "ADOBE INC.", _E),
    ("v-google", "All Google apps (Windows)", "Google", "GOOGLE LLC", _E),
    ("v-mozilla", "All Mozilla apps (Windows)", "Mozilla", "MOZILLA CORPORATION", _E),
    ("v-zoom", "All Zoom apps (Windows)", "Zoom", "ZOOM COMMUNICATIONS, INC.", _E),
    ("v-vmware", "All VMware apps (Windows)", "VMware", "VMWARE, INC.", _E),
    ("v-wireshark", "Wireshark Foundation", "Wireshark", "WIRESHARK FOUNDATION", _E),
    ("v-valve", "All Valve / Steam apps", "Valve", "VALVE CORP.", _E),
    ("v-epic", "All Epic Games apps", "Epic Games", "EPIC GAMES INC.", _E),
    ("v-discord", "All Discord apps", "Discord", "DISCORD INC.", _E),
    ("v-apple", "All Apple apps (Windows: iTunes, iCloud)", "Apple", "APPLE INC.", _E),
    ("v-dell", "All Dell apps and drivers", "Dell", "DELL TECHNOLOGIES INC.", _E),
    ("v-hpinc", "All HP Inc. apps and drivers", "HP", "HP INC.", _E),
    ("v-hpco", "Hewlett-Packard Company (older HP software)", "HP", "HEWLETT-PACKARD COMPANY", _E),
    ("v-nvidia", "All NVIDIA drivers and apps", "NVIDIA", "NVIDIA CORPORATION", _E),
    ("v-amd", "All AMD drivers and apps", "AMD", "ADVANCED MICRO DEVICES", _E),
    ("v-asus", "All ASUS apps and drivers", "ASUS", "ASUSTEK COMPUTER INC.", _E),
    ("v-corsair", "All Corsair apps", "Corsair", "CORSAIR MEMORY, INC.", _E),
    ("v-broadcom", "All Broadcom drivers", "Broadcom", "BROADCOM INC", _E),
    ("v-paessler", "Paessler PRTG (AG)", "Paessler", "PAESSLER AG", _E),
    ("v-intel", "All Intel drivers and apps", "Intel", "INTEL CORPORATION", _V),
    ("v-realtek", "Realtek drivers", "Realtek", "REALTEK SEMICONDUCTOR CORP.", _V),
    ("v-lenovo", "All Lenovo apps and drivers", "Lenovo", "LENOVO", _V),
    ("v-cisco", "All Cisco apps (Webex, Secure Client)", "Cisco", "CISCO SYSTEMS, INC.", _V),
    ("v-citrix", "All Citrix apps", "Citrix", "CITRIX SYSTEMS, INC.", _V),
    ("v-oracle", "All Oracle apps (Java, VirtualBox)", "Oracle", "ORACLE CORPORATION", _V),
    ("v-slack", "All Slack apps", "Slack", "SLACK TECHNOLOGIES, LLC", _V),
    ("v-dropbox", "All Dropbox apps", "Dropbox", "DROPBOX, INC.", _V),
]:
    vendor_win(k, n, v, p, t)

# ---- Windows: more Microsoft ----
win("onedrive", "Microsoft OneDrive", "Microsoft", "MICROSOFT CORPORATION", PF + "Microsoft OneDrive\\", "OneDrive.exe", "Microsoft.OneDrive", _E)
win("teams", "Microsoft Teams", "Microsoft", "MICROSOFT CORPORATION", "", "ms-teams.exe", "Microsoft.Teams", _E)
for k, n, pr in [("word", "Word", "WINWORD.EXE"), ("excel", "Excel", "EXCEL.EXE"), ("ppt", "PowerPoint", "POWERPNT.EXE"),
                 ("outlook", "Outlook", "OUTLOOK.EXE"), ("onenote", "OneNote", "ONENOTE.EXE"),
                 ("access", "Access", "MSACCESS.EXE"), ("visio", "Visio", "VISIO.EXE"), ("project", "Project", "WINPROJ.EXE")]:
    win("o-" + k, f"Microsoft {n} (Microsoft 365 / Office)", "Microsoft", "MICROSOFT CORPORATION", OFF, pr, None, _E)
win("powertoys", "Microsoft PowerToys", "Microsoft", "MICROSOFT CORPORATION", PF + "PowerToys\\", "PowerToys.exe", "Microsoft.PowerToys", _E)
win("pwsh", "PowerShell 7", "Microsoft", "MICROSOFT CORPORATION", PF + "PowerShell\\7\\", "pwsh.exe", "Microsoft.PowerShell", _E)
win("winterm", "Windows Terminal", "Microsoft", "MICROSOFT CORPORATION", "", "wt.exe", "Microsoft.WindowsTerminal", _E)
win("vs2022", "Visual Studio 2022 Community", "Microsoft", "MICROSOFT CORPORATION", PF + "Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\", "devenv.exe", "Microsoft.VisualStudio.2022.Community", _E)
win("powerbi", "Power BI Desktop", "Microsoft", "MICROSOFT CORPORATION", PF + "Microsoft Power BI Desktop\\bin\\", "PBIDesktop.exe", "Microsoft.PowerBI", _E)

# ---- Windows: more Adobe (year-versioned folders use * - Photoshop etc. have no winget package) ----
win("acropro", "Adobe Acrobat Pro", "Adobe", "ADOBE INC.", PF + "Adobe\\Acrobat DC\\Acrobat\\", "Acrobat.exe", "Adobe.Acrobat.Pro", _E)
win("cc", "Adobe Creative Cloud", "Adobe", "ADOBE INC.", PF86 + "Adobe\\Adobe Creative Cloud\\ACC\\", "Creative Cloud.exe", "Adobe.CreativeCloud", _E)
win("ps", "Adobe Photoshop", "Adobe", "ADOBE INC.", PF + "Adobe\\Adobe Photoshop *\\", "Photoshop.exe", None, _E)
win("ai", "Adobe Illustrator", "Adobe", "ADOBE INC.", PF + "Adobe\\Adobe Illustrator *\\Support Files\\Contents\\Windows\\", "Illustrator.exe", None, _E)
win("pr", "Adobe Premiere Pro", "Adobe", "ADOBE INC.", PF + "Adobe\\Adobe Premiere Pro *\\", "Adobe Premiere Pro.exe", None, _E)
win("ae", "Adobe After Effects", "Adobe", "ADOBE INC.", PF + "Adobe\\Adobe After Effects *\\Support Files\\", "AfterFX.exe", None, _E)
win("id", "Adobe InDesign", "Adobe", "ADOBE INC.", PF + "Adobe\\Adobe InDesign *\\", "InDesign.exe", None, _E)
win("lrc", "Adobe Lightroom Classic", "Adobe", "ADOBE INC.", PF + "Adobe\\Adobe Lightroom Classic\\", "lightroom.exe", None, _E)

# ---- Windows: Google, Mozilla and others ----
win("gdrive", "Google Drive", "Google", "GOOGLE LLC", PF + "Google\\Drive File Stream\\", "GoogleDriveFS.exe", "Google.GoogleDrive", _E)
win("thunderbird", "Mozilla Thunderbird", "Mozilla", "MOZILLA CORPORATION", PF + "Mozilla Thunderbird\\", "thunderbird.exe", "Mozilla.Thunderbird", _E)
win("slack", "Slack (per-user install)", "Slack", "SLACK TECHNOLOGIES, LLC", "", "slack.exe", "SlackTechnologies.Slack")
win("winscp", "WinSCP", "WinSCP", "MARTIN PRIKRYL", PF86 + "WinSCP\\", "WinSCP.exe", "WinSCP.WinSCP")
win("git", "Git for Windows", "Git", "JOHANNES SCHINDELIN", PF + "Git\\", "git.exe", "Git.Git")
win("node", "Node.js (LTS)", "OpenJS", "OPENJS FOUNDATION", PF + "nodejs\\", "node.exe", "OpenJS.NodeJS.LTS")
win("docker", "Docker Desktop", "Docker", "DOCKER INC", PF + "Docker\\Docker\\", "Docker Desktop.exe", "Docker.DockerDesktop")
win("citrix", "Citrix Workspace", "Citrix", "CITRIX SYSTEMS, INC.", PF86 + "Citrix\\ICA Client\\", "wfica32.exe", "Citrix.Workspace")
win("webex", "Cisco Webex", "Cisco", "CISCO SYSTEMS, INC.", "", "CiscoCollabHost.exe", "Cisco.Webex")
win("anydesk", "AnyDesk", "AnyDesk", "PHILANDRO SOFTWARE GMBH", PF86 + "AnyDesk\\", "AnyDesk.exe", "AnyDesk.AnyDesk")
win("1password", "1Password (per-user install)", "1Password", "AGILEBITS INC.", "", "1Password.exe", "AgileBits.1Password")
win("spotify", "Spotify (per-user install)", "Spotify", "SPOTIFY AB", "", "Spotify.exe", "Spotify.Spotify")
win("steam", "Steam", "Valve", "VALVE CORP.", PF86 + "Steam\\", "steam.exe", "Valve.Steam", _E)
win("epic", "Epic Games Launcher", "Epic Games", "EPIC GAMES INC.", PF86 + "Epic Games\\Launcher\\Portal\\Binaries\\Win64\\", "EpicGamesLauncher.exe", "EpicGames.EpicGamesLauncher", _E)
win("virtualbox", "Oracle VirtualBox", "Oracle", "ORACLE CORPORATION", PF + "Oracle\\VirtualBox\\", "VirtualBox.exe", "Oracle.VirtualBox")
win("vmwarews", "VMware Workstation Pro", "VMware", "VMWARE, INC.", PF86 + "VMware\\VMware Workstation\\", "vmware.exe", "VMware.WorkstationPro", _E)
win("foxit", "Foxit PDF Reader", "Foxit", "FOXIT SOFTWARE INC.", PF86 + "Foxit Software\\Foxit PDF Reader\\", "FoxitPDFReader.exe", "Foxit.FoxitReader")

# ---- macOS: whole-vendor rules by Team ID (Publisher on macOS is the 10-character Team ID) ----
for k, n, v, t, tr in [
    ("m-ms", "All Microsoft apps (macOS)", "Microsoft", "UBF8T346G9", _E),
    ("m-adobe", "All Adobe apps (macOS)", "Adobe", "JQ525L2MZD", _E),
    ("m-google", "All Google apps (macOS)", "Google", "EQHXZ8M8AV", _E),
    ("m-mozilla", "All Mozilla apps (macOS)", "Mozilla", "43AQ936H96", _E),
    ("m-cisco", "All Cisco apps (macOS)", "Cisco", "DE8Y96K9QP", _E),
    ("m-logi", "All Logitech apps (macOS)", "Logitech", "QED4VVPZWA", _E),
    ("m-bmd", "All Blackmagic Design apps (macOS)", "Blackmagic", "9ZGFBWLSYP", _E),
    ("m-sony", "All Sony apps (macOS)", "Sony", "VH49J2FYHE", _E),
    ("m-rode", "All RODE apps (macOS)", "RODE", "Z9T72PWTJA", _E),
    ("m-vmware", "All VMware apps (macOS)", "VMware", "EG7KH642X6", _E),
    ("m-oracle", "All Oracle apps (macOS)", "Oracle", "VB5E2TV963", _E),
    ("m-anthropic", "Claude Desktop (macOS)", "Anthropic", "Q6L2SF6YDW", _E),
    ("m-vlc", "VLC / VideoLAN (macOS)", "VideoLAN", "75GAHG3SZQ", _E),
    ("m-silabs", "Silicon Labs (macOS)", "Silicon Labs", "52444FG85C", _E),
    ("m-zoom", "All Zoom apps (macOS)", "Zoom", "BJ4HAAB9B3", _V),
    ("m-slack", "All Slack apps (macOS)", "Slack", "BQR82RBBHL", _V),
    ("m-dropbox", "All Dropbox apps (macOS)", "Dropbox", "G7HH3F8CAK", _V),
    ("m-1pw", "All 1Password apps (macOS)", "1Password", "2BUA8C4S2C", _V),
    ("m-docker", "All Docker apps (macOS)", "Docker", "9BNSXJN65R", _V),
    ("m-jetbrains", "All JetBrains apps (macOS)", "JetBrains", "2ZEFAR8TH3", _V),
    ("m-brave", "All Brave apps (macOS)", "Brave", "KL8N8XSYF4", _V),
    ("m-tv", "All TeamViewer apps (macOS)", "TeamViewer", "H7UGFBUGV6", _V),
    ("m-spotify", "All Spotify apps (macOS)", "Spotify", "2FNC3A47ZF", _V),
    ("m-notion", "All Notion apps (macOS)", "Notion", "LBQJ96FQ8D", _V),
    ("m-postman", "All Postman apps (macOS)", "Postman", "H7H8Q7M5CK", _V),
    ("m-signal", "Signal (macOS)", "Signal", "U68MSDN6DR", _V),
    ("m-telegram", "Telegram (macOS)", "Telegram", "6N38VWS5BX", _V),
    ("m-citrix", "All Citrix apps (macOS)", "Citrix", "S272Y5R93J", _V),
    ("m-iterm", "iTerm2 (macOS)", "iTerm2", "H7V7XYVQ7D", _V),
    ("m-wireshark", "Wireshark (macOS)", "Wireshark", "7Z6EMTD2C6", _V),
]:
    vendor_mac(k, n, v, t, tr)

# ---- macOS: Apple's own locations (rules seen in your console export; Apple-signed apps have no Team ID) ----
for k, g in [("sys-lib", "/System/Library/**"), ("sys-apps", "/System/Applications/**"), ("usr-bin", "/usr/bin/*"),
             ("usr-libexec", "/usr/libexec/*"), ("usr-sbin", "/usr/sbin/*"),
             ("cryptex", "/System/Volumes/Preboot/Cryptexes/App/**"), ("ios-support", "/System/iOSSupport/System/Library/**")]:
    path_mac("p-" + k, f"macOS system: {g}", g)

# ---- macOS: individual apps (Team ID + app bundle; versions from the Homebrew cask feed) ----
mac("m-chrome", "Google Chrome", "Google", "EQHXZ8M8AV", "Google Chrome", "Google Chrome", "google-chrome", _E)
mac("m-firefox", "Mozilla Firefox", "Mozilla", "43AQ936H96", "Firefox", "firefox", "firefox", _E)
mac("m-thunderbird", "Mozilla Thunderbird", "Mozilla", "43AQ936H96", "Thunderbird", "thunderbird", "thunderbird", _E)
mac("m-gdrive", "Google Drive", "Google", "EQHXZ8M8AV", "Google Drive", "Google Drive", "google-drive", _E)
mac("m-edge", "Microsoft Edge", "Microsoft", "UBF8T346G9", "Microsoft Edge", "Microsoft Edge", "microsoft-edge", _E)
mac("m-teams", "Microsoft Teams", "Microsoft", "UBF8T346G9", "Microsoft Teams", "MSTeams", "microsoft-teams", _E)
mac("m-word", "Microsoft Word", "Microsoft", "UBF8T346G9", "Microsoft Word", "Microsoft Word", "microsoft-word", _E)
mac("m-excel", "Microsoft Excel", "Microsoft", "UBF8T346G9", "Microsoft Excel", "Microsoft Excel", "microsoft-excel", _E)
mac("m-ppt", "Microsoft PowerPoint", "Microsoft", "UBF8T346G9", "Microsoft PowerPoint", "Microsoft PowerPoint", "microsoft-powerpoint", _E)
mac("m-outlook", "Microsoft Outlook", "Microsoft", "UBF8T346G9", "Microsoft Outlook", "Microsoft Outlook", "microsoft-outlook", _E)
mac("m-onedrive", "Microsoft OneDrive", "Microsoft", "UBF8T346G9", "OneDrive", "OneDrive", "onedrive", _E)
mac("m-vscode", "Visual Studio Code", "Microsoft", "UBF8T346G9", "Visual Studio Code", "Electron", "visual-studio-code", _E)
mac("m-acrobat", "Adobe Acrobat Reader", "Adobe", "JQ525L2MZD", "Adobe Acrobat Reader", "AdobeReader", "adobe-acrobat-reader", _E)
mac("m-cc", "Adobe Creative Cloud", "Adobe", "JQ525L2MZD", "Adobe Creative Cloud", "Creative Cloud", "adobe-creative-cloud", _E)
mac("m-claude", "Claude", "Anthropic", "Q6L2SF6YDW", "Claude", "Claude", "claude", _E)
mac("m-vlc-app", "VLC media player", "VideoLAN", "75GAHG3SZQ", "VLC", "VLC", "vlc", _E)
mac("m-webex", "Cisco Webex", "Cisco", "DE8Y96K9QP", "Webex", "Webex", "webex", _E)
mac("m-vbox", "Oracle VirtualBox", "Oracle", "VB5E2TV963", "VirtualBox", "VirtualBox", "virtualbox", _E)
mac("m-fusion", "VMware Fusion", "VMware", "EG7KH642X6", "VMware Fusion", "VMware Fusion", "vmware-fusion", _E)
mac("m-zoom-app", "Zoom Workplace", "Zoom", "BJ4HAAB9B3", "zoom.us", "zoom.us", "zoom")
mac("m-slack-app", "Slack", "Slack", "BQR82RBBHL", "Slack", "Slack", "slack")
mac("m-brave-app", "Brave", "Brave", "KL8N8XSYF4", "Brave Browser", "Brave Browser", "brave-browser")
mac("m-dropbox-app", "Dropbox", "Dropbox", "G7HH3F8CAK", "Dropbox", "Dropbox", "dropbox")
mac("m-1pw-app", "1Password", "1Password", "2BUA8C4S2C", "1Password", "1Password", "1password")
mac("m-spotify-app", "Spotify", "Spotify", "2FNC3A47ZF", "Spotify", "Spotify", "spotify")
mac("m-tv-app", "TeamViewer", "TeamViewer", "H7UGFBUGV6", "TeamViewer", "TeamViewer", "teamviewer")
mac("m-notion-app", "Notion", "Notion", "LBQJ96FQ8D", "Notion", "Notion", "notion")
mac("m-postman-app", "Postman", "Postman", "H7H8Q7M5CK", "Postman", "Postman", "postman")
mac("m-signal-app", "Signal", "Signal", "U68MSDN6DR", "Signal", "Signal", "signal")
mac("m-telegram-app", "Telegram", "Telegram", "6N38VWS5BX", "Telegram", "Telegram", "telegram")
mac("m-docker-app", "Docker Desktop", "Docker", "9BNSXJN65R", "Docker", "Docker Desktop", "docker-desktop")
mac("m-jb-app", "JetBrains Toolbox", "JetBrains", "2ZEFAR8TH3", "JetBrains Toolbox", "jetbrains-toolbox", "jetbrains-toolbox")
mac("m-citrix-app", "Citrix Workspace", "Citrix", "S272Y5R93J", "Citrix Workspace", "Citrix Workspace", "citrix-workspace")
mac("m-iterm-app", "iTerm2", "iTerm2", "H7V7XYVQ7D", "iTerm", "iTerm2", "iterm2")
mac("m-wireshark-app", "Wireshark", "Wireshark", "7Z6EMTD2C6", "Wireshark", "Wireshark", "wireshark-app")


BUILTIN_COUNT = len(SEED)   # entries defined in code above; the bundled CSV below is added after this point

# ---------------------------------------------------------------------------------------------------
# Bundled seed file (catalog_seed.csv, next to this file): sanitised apps harvested from real consoles via
# tools/sanitize_csv.py. Read-only at runtime, shipped in the image, human-editable and diff-able in git.
# ---------------------------------------------------------------------------------------------------
def _load_seed_csv():
    import csv as _csv
    f = Path(__file__).with_name("catalog_seed.csv")
    if not f.is_file():
        return
    with open(f, encoding="utf-8", newline="") as fh:
        for r in _csv.DictReader(fh):
            k = "s-" + hashlib.sha1("|".join([r["os"], r["name"], r["publisher"], r["version"], r["install_path"], r["kind"]]).lower().encode()).hexdigest()[:12]
            _add(k, r["name"], r["publisher"] or "Unknown publisher", r["os"], r["publisher"], r["install_path"], r["process"],
                 None, _E, r["kind"] or "app")
            SEED[-1].update(version=r.get("version", ""), hash=r.get("hash", ""))


_load_seed_csv()


def _empty(e):
    return {"id": f"common-{e['key']}", "name": e["name"], "vendor": e["vendor"], "os": e["os"], "kind": e["kind"],
            "publisher": e["publisher"], "install_path": e["install_path"], "process": e["process"],
            "trust": e["trust"], "updatable": bool(e["source"]), "version": e.get("version", ""), "hash": e.get("hash", ""), "installer_sha256": "",
            "installer_url": "", "updated_at": "", "status": "never updated" if e["source"] else "static", "error": ""}


MUTABLE = ("version", "installer_sha256", "installer_url", "updated_at", "status", "error")


class RateLimited(RuntimeError):
    pass


def _cache_file(data_dir):
    return Path(data_dir) / "catalog_cache.json"


def load(data_dir):
    cache = {}
    try:
        cache = json.loads(_cache_file(data_dir).read_text())
    except (OSError, ValueError):
        pass
    apps = []
    for e in SEED:
        a = _empty(e)
        a.update({k: v for k, v in (cache.get(a["id"]) or {}).items() if k in MUTABLE})
        apps.append(a)
    return apps


def _save(data_dir, apps):
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    _cache_file(data_dir).write_text(json.dumps({a["id"]: {k: a[k] for k in MUTABLE} for a in apps}, indent=1))


def _manifest_dir(winget_id):
    parts = winget_id.split(".")
    return "manifests/" + parts[0][0].lower() + "/" + "/".join(parts)


def _version_key(v):
    return [int(x) for x in re.split(r"[.]", v)]


def _latest_versions(winget_id, get=None):
    """Newest-first release folders from the repo. Uses the git trees API (not the contents API,
    which is capped at 1000 entries and would hide the newest versions of big packages)."""
    get = get or requests.get
    url = ("https://api.github.com/repos/microsoft/winget-pkgs/git/trees/master:"
           + quote(_manifest_dir(winget_id), safe="/"))
    r = get(url, headers=HEADERS, timeout=TIMEOUT)
    if r.status_code in (403, 429) and ("rate limit" in r.text.lower() or r.status_code == 429):
        raise RateLimited("GitHub rate limit reached - set GITHUB_TOKEN in docker-compose.yml, or try again in an hour")
    if r.status_code == 404:
        raise RuntimeError("package not found in winget")
    r.raise_for_status()
    vers = [t["path"] for t in r.json().get("tree", [])
            if t.get("type") == "tree" and re.fullmatch(r"\d+(\.\d+)*", t["path"])]
    return sorted(vers, key=_version_key, reverse=True)


def parse_installer_yaml(text):
    """Pick the preferred installer (x64, en-US/no locale, exe/msi/etc. over msix) -> (sha256, url)."""
    block = text.split("\nInstallers:", 1)[-1]
    entries = re.split(r"\n- (?=\S)", "\n" + block.strip("\n"))
    best, best_score = None, -1
    for ent in entries:
        sha = re.search(r"InstallerSha256:\s*([0-9A-Fa-f]{64})", ent)
        if not sha:
            continue
        url = re.search(r"InstallerUrl:\s*(\S+)", ent)
        arch = re.search(r"Architecture:\s*(\S+)", ent)
        loc = re.search(r"InstallerLocale:\s*(\S+)", ent)
        typ = re.search(r"InstallerType:\s*(\S+)", ent)
        score = 0
        score += 4 if arch and arch.group(1) == "x64" else (2 if arch and arch.group(1) == "neutral" else 0)
        score += 2 if (not loc or loc.group(1).lower().startswith("en-us")) else 0
        score += 1 if not typ or typ.group(1) not in ("msix", "appx") else 0
        if score > best_score:
            best, best_score = (sha.group(1).upper(), url.group(1) if url else ""), score
    if not best:
        raise RuntimeError("no installer hash in manifest")
    return best


def fetch_winget(wid, get=None):
    get = get or requests.get
    last_err = "no usable manifest"
    for ver in _latest_versions(wid, get)[:3]:
        raw = (f"https://raw.githubusercontent.com/microsoft/winget-pkgs/master/"
               f"{quote(_manifest_dir(wid), safe='/')}/{ver}/{quote(wid)}.installer.yaml")
        r = get(raw, timeout=TIMEOUT, headers={"User-Agent": "AppControlUI"})
        if r.status_code == 200:
            try:
                sha, url = parse_installer_yaml(r.text)
                return {"version": ver, "installer_sha256": sha, "installer_url": url}
            except RuntimeError as e:
                last_err = str(e)
        else:
            last_err = f"manifest {ver} returned {r.status_code}"
    raise RuntimeError(last_err)


def fetch_brew(token, get=None):
    """Homebrew cask feed: version + sha256 of the .dmg/.pkg (sha256 'no_check' = self-updating app, no fixed hash)."""
    get = get or requests.get
    r = get(f"https://formulae.brew.sh/api/cask/{quote(token)}.json", timeout=TIMEOUT,
            headers={"User-Agent": "AppControlUI"})
    if r.status_code == 404:
        raise RuntimeError(f"cask '{token}' not found")
    r.raise_for_status()
    j = r.json()
    sha = j.get("sha256") or ""
    return {"version": str(j.get("version", "")).split(",")[0],
            "installer_sha256": sha.upper() if re.fullmatch(r"[0-9a-fA-F]{64}", sha) else "",
            "installer_url": j.get("url") or ""}


def fetch_one(entry, get=None):
    kind, ident = entry["source"]
    return fetch_winget(ident, get) if kind == "winget" else fetch_brew(ident, get)


def update_all(data_dir, ids=None, progress=lambda **k: None, get=None, workers=4):
    """Update the given catalog ids (or every updatable entry). Entries without a public source are skipped."""
    apps = load(data_dir)
    by_id = {"common-" + e["key"]: e for e in SEED}
    todo = [a for a in apps if by_id[a["id"]]["source"] and (not ids or a["id"] in ids)]
    done, limited = 0, {"hit": False}
    progress(stage="Fetching latest versions", done=0, total=len(todo))

    def work(a):
        if limited["hit"] and by_id[a["id"]]["source"][0] == "winget":
            a["status"], a["error"] = "update failed", "skipped - GitHub rate limit reached"
            return
        try:
            a.update(fetch_one(by_id[a["id"]], get))
            a.update(status="ok", error="", updated_at=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
        except RateLimited as e:
            limited["hit"] = True
            a["status"], a["error"] = "update failed", str(e)
        except Exception as e:  # keep the previous values, record why
            a["status"], a["error"] = "update failed", str(e)[:200]

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for f in [ex.submit(work, a) for a in todo]:
            f.result(); done += 1
            progress(stage="Fetching latest versions", done=done, total=len(todo))
    _save(data_dir, apps)
    return apps, len(todo), limited["hit"]


# ---------------------------------------------------------------------------------------------------
# "Learned" applications - every inventory fetch is remembered here (data/learned_apps.json) so the
# Common list grows with what your own endpoints report. Never touched by the internet Update.
# ---------------------------------------------------------------------------------------------------
_LEARN_LOCK = threading.Lock()
LEARN_CAP = 20000


def _learned_file(data_dir):
    return Path(data_dir) / "learned_apps.json"


def _read_learned(data_dir):
    try:
        d = json.loads(_learned_file(data_dir).read_text())
        # Windows + macOS only: silently drops anything else (e.g. Linux learned by an earlier version)
        return {k: v for k, v in d.items() if v.get("os") in ("WINDOWS", "MACOS")} if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _learn_os(row):
    o = (row.get("os") or "").upper()
    if "MAC" in o or "OSX" in o:
        return "MACOS"
    if o:
        return "WINDOWS" if "WIN" in o else "OTHER"
    return "MACOS" if (row.get("install_path") or "").startswith("/") else "WINDOWS"


def learn(data_dir, rows, source=""):
    """Remember inventory rows. Returns (new, updated). Key ignores version/hash so newer ones replace older."""
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    new = upd = 0
    with _LEARN_LOCK:
        store = _read_learned(data_dir)
        for r in rows:
            name = (r.get("name") or "").strip()
            if not name:
                continue
            os_ = _learn_os(r)
            if os_ not in ("WINDOWS", "MACOS"):
                continue
            pub = (r.get("publisher") or "").strip()
            path = (r.get("install_path") or "").strip()
            key = "|".join([os_, name, pub, path]).lower()
            lid = "learned-" + hashlib.sha1(key.encode()).hexdigest()[:12]
            cur = store.get(lid)
            ent = {"id": lid, "name": name, "vendor": pub or "Unknown publisher", "os": os_, "kind": "app", "publisher": pub,
                   "install_path": path, "process": r.get("process") or (cur or {}).get("process", ""),
                   "version": r.get("version") or "", "hash": r.get("hash") or (cur or {}).get("hash", ""),
                   "trust": "learned", "updatable": False, "installer_sha256": "", "installer_url": "",
                   "updated_at": "", "status": "learned", "error": "", "last_seen": now}
            if cur:
                ent["first_seen"] = cur.get("first_seen", now)
                ent["seen_count"] = cur.get("seen_count", 1) + 1
                srcs = cur.get("seen_in", [])
                upd += 1
            else:
                if len(store) >= LEARN_CAP:
                    continue
                ent["first_seen"], ent["seen_count"], srcs = now, 1, []
                new += 1
            if source and source not in srcs:
                srcs = (srcs + [source])[-5:]
            ent["seen_in"] = srcs
            store[lid] = ent
        if new or upd:
            Path(data_dir).mkdir(parents=True, exist_ok=True)
            tmp = _learned_file(data_dir).with_suffix(".tmp")
            tmp.write_text(json.dumps(store, indent=1))
            tmp.replace(_learned_file(data_dir))
    return new, upd


def load_learned(data_dir):
    return sorted(_read_learned(data_dir).values(), key=lambda a: (a["name"].lower(), a["install_path"].lower()))


def forget(data_dir, ids=None):
    """Delete learned entries by id, or all of them when ids is None. Returns how many were removed."""
    with _LEARN_LOCK:
        store = _read_learned(data_dir)
        keep = {} if ids is None else {k: v for k, v in store.items() if k not in ids}
        removed = len(store) - len(keep)
        if removed:
            _learned_file(data_dir).write_text(json.dumps(keep, indent=1))
    return removed
