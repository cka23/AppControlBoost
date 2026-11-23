(() => {
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const S = { url: "", token: "", rows: [], selected: new Set(), staged: new Map(), planSel: new Set(),
            published: [], common: [], exports: [], filter: "", tab: "inst", rtab: "plan", osFilter: "", gen: true, grouped: false, open: new Set(), limit: { inst: 500, com: 500 }, accounts: [], sites: [], groups: [], busy: false };

const store = {
  get(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};
S.gen = store.get("acui.gen", true);
const sess = {
  get(k) { try { return sessionStorage.getItem(k) || ""; } catch { return ""; } },
  set(k, v) { try { sessionStorage.setItem(k, v); } catch {} },
  clear() { try { sessionStorage.clear(); } catch {} },
};

async function api(path, opts = {}) {
  const headers = { "X-S1-URL": S.url, "X-S1-Token": S.token, ...(opts.headers || {}) };
  if (opts.json) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  const r = await fetch(path, { method: opts.method || "GET", headers, body: opts.body });
  let data = {}; try { data = await r.json(); } catch {}
  if (!r.ok) {
    if (r.status === 401 && S.token) { signOut("Session expired - please sign in again."); }
    throw new Error(data.error || `Request failed (${r.status})`);
  }
  return data;
}
function toast(html, ms = 5000) {
  const t = $("toast"); t.innerHTML = html; t.classList.remove("hidden");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), ms);
}
// C:\Users\Bryon\AppData\Roaming\Zoom\bin\  ->  C:\Users\*\AppData\Roaming\Zoom\bin\   (and /Users/bob/... on macOS)
const SHARED_PROFILES = /^(public|default|default user|all users|shared)$/i;
function genPath(p) {
  if (!S.gen || !p) return p || "";
  let m = p.match(/^([A-Za-z]:\\Users\\)([^\\]+)(\\.*)?$/i);
  if (m && !SHARED_PROFILES.test(m[2])) return m[1] + "*" + (m[3] || "");
  m = p.match(/^(\/Users\/)([^\/]+)(\/.*)?$/);
  if (m && !SHARED_PROFILES.test(m[2])) return m[1] + "*" + (m[3] || "");
  return p;
}
const ruleKey = (r) => [r["Rule Name"], r["Path"], r["Hash SHA-256"]].join("|").toLowerCase();

// header logo: drop an official logo.svg or logo.png into ./brand (mounted at /brand) - nothing is bundled
(() => {
  const img = $("logo"); const tries = ["/brand/logo.svg", "/brand/logo.png"]; let i = 0;
  img.onload = () => { img.classList.remove("hidden"); $("favicon").href = img.src; };   // same file is the tab icon
  img.onerror = () => { i++; if (i < tries.length) img.src = tries[i]; else img.classList.add("hidden"); };
  img.src = tries[0];
})();

// ---------------- login ----------------
function showLogin(msg = "") {
  $("app").classList.add("hidden"); $("login").classList.remove("hidden");
  $("url").value = store.get("acui.url", ""); $("loginErr").textContent = msg;
}
function signOut(msg) { S.token = ""; sess.clear(); showLogin(msg || ""); }
$("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault(); $("loginErr").textContent = ""; $("loginBtn").disabled = true;
  S.url = $("url").value.trim(); S.token = $("token").value.trim();
  try {
    const d = await api("/api/login", { method: "POST", json: {} });
    sess.set("url", S.url); sess.set("token", S.token); store.set("acui.url", S.url);
    $("token").value = ""; enterApp(d);
  } catch (err) { S.token = ""; $("loginErr").textContent = err.message; }
  finally { $("loginBtn").disabled = false; }
});
$("logout").onclick = () => signOut();

function enterApp(d) {
  $("login").classList.add("hidden"); $("app").classList.remove("hidden");
  $("who").textContent = `${d.user.email || "API user"}${d.user.role ? " · " + d.user.role : ""}`;
  S.accounts = d.accounts || [];
  $("account").innerHTML = S.accounts.length
    ? S.accounts.map((a) => `<option value="${esc(a.id)}">${esc(a.name)}</option>`).join("")
    : `<option value="">No accounts visible</option>`;
  const w = $("warnings"); if (d.warning) { w.textContent = d.warning; w.classList.remove("hidden"); } else w.classList.add("hidden");
  S.staged = new Map(store.get("acui.staged", []));
  onAccountChange(); refreshPublished(); refreshExports(); loadCatalog(); renderAll();
}

// ---------------- scope ----------------
async function loadSites(q = "") {
  const acc = $("account").value; if (!acc) return;
  const sel = $("site"); sel.innerHTML = `<option value="">All sites in account</option>`;
  try {
    const d = await api(`/api/sites?accountId=${encodeURIComponent(acc)}&q=${encodeURIComponent(q)}`);
    S.sites = d.sites;
    sel.innerHTML += d.sites.map((s) => `<option value="${esc(s.id)}">${esc(s.name)}${s.state && s.state !== "active" ? " (" + esc(s.state) + ")" : ""}</option>`).join("");
    if (d.sites.length >= 100) toast("Showing the first 100 sites - use the search box to narrow down.");
  } catch (e) { toast(esc(e.message)); }
  onSiteChange();
}
async function onSiteChange() {
  const sid = $("site").value, g = $("group");
  g.innerHTML = `<option value="">All groups in site</option>`; g.disabled = !sid;
  if (sid) {
    try { const d = await api(`/api/groups?siteId=${encodeURIComponent(sid)}`); S.groups = d.groups;
      g.innerHTML += d.groups.map((x) => `<option value="${esc(x.id)}">${esc(x.name)} (${x.totalAgents ?? 0})</option>`).join("");
    } catch (e) { toast(esc(e.message)); }
  }
  updateScopeNote();
}
function onAccountChange() { $("siteQ").value = ""; loadSites(); }
function currentScope() {
  const acc = S.accounts.find((a) => a.id === $("account").value);
  const site = S.sites.find((s) => s.id === $("site").value);
  const grp = S.groups.find((g) => g.id === $("group").value);
  if (site && grp) return { type: "group", id: grp.id, siteId: site.id, groupName: grp.name, siteName: site.name, label: `Group ${grp.name} / Site ${site.name}` };
  if (site) return { type: "site", id: site.id, siteName: site.name, label: `Site ${site.name}` };
  if (acc) return { type: "account", id: acc.id, siteName: acc.name, label: `Account ${acc.name}` };
  return null;
}
function updateScopeNote() {
  const sc = currentScope(), n = $("scopeNote");
  n.textContent = sc ? `Scope: ${sc.label}` : ""; n.classList.toggle("hidden", !sc);
}
$("account").onchange = onAccountChange;
$("site").onchange = onSiteChange;
$("group").onchange = updateScopeNote;
let sq; $("siteQ").oninput = (e) => { clearTimeout(sq); sq = setTimeout(() => loadSites(e.target.value.trim()), 350); };

// ---------------- inventory ----------------
const PROG = { t0: 0, stage: "", stageT0: 0, jobId: "", timer: null };
const fmtT = (ms) => { const t = Math.max(0, Math.round(ms / 1000)); return `${Math.floor(t / 60)}:${String(t % 60).padStart(2, "0")}`; };
function startProg(label, withHashes) {
  Object.assign(PROG, { t0: Date.now(), stage: "", stageT0: Date.now(), jobId: "", hashes: withHashes });
  $("pgScope").textContent = label; $("pgStep").textContent = ""; $("pgStage").textContent = "Starting…";
  $("pgFill").style.width = ""; $("pgFill").parentNode.classList.add("indet"); $("pgCount").textContent = "";
  $("pgCancel").disabled = false; $("pgCancel").textContent = "Cancel";
  if (!$("prog").open) $("prog").showModal();
  clearInterval(PROG.timer); PROG.timer = setInterval(() => { $("pgTime").textContent = "Elapsed " + fmtT(Date.now() - PROG.t0) + (PROG.eta || ""); }, 500);
}
function updProg(p = {}) {
  const stage = p.stage || "";
  if (stage !== PROG.stage) { PROG.stage = stage; PROG.stageT0 = Date.now(); }
  const n = PROG.hashes ? 3 : 2, step = /listing/i.test(stage) ? 1 : /telemetry|hash/i.test(stage) ? 3 : 2;
  $("pgStep").textContent = `Step ${step} of ${n}`; $("pgStage").textContent = "· " + stage;
  const bar = $("pgFill").parentNode;
  if (p.total) {
    const pct = Math.round(100 * p.done / p.total);
    bar.classList.remove("indet"); $("pgFill").style.width = pct + "%";
    $("pgCount").textContent = `${p.done.toLocaleString()} of ${p.total.toLocaleString()} (${pct}%)`;
    const el = Date.now() - PROG.stageT0;
    PROG.eta = p.done >= 5 && p.done < p.total ? ` · about ${fmtT(el / p.done * (p.total - p.done))} left in this step` : "";
  } else { bar.classList.add("indet"); $("pgFill").style.width = ""; $("pgCount").textContent = ""; PROG.eta = ""; }
}
function endProg() { clearInterval(PROG.timer); if ($("prog").open) $("prog").close(); }
$("prog").addEventListener("cancel", (e) => e.preventDefault());   // Esc must not hide a running job
$("pgCancel").onclick = async () => {
  $("pgCancel").disabled = true; $("pgCancel").textContent = "Cancelling…";
  if (PROG.jobId) { try { await api(`/api/inventory/${PROG.jobId}/cancel`, { method: "POST", json: {} }); } catch {} }
};
$("fetch").onclick = async () => {
  const sc = currentScope(); if (!sc || S.busy) return;
  let learned = null, cancelled = false;
  S.siteName = sc.siteName; S.busy = true; $("fetch").disabled = true; S.rows = []; S.selected.clear(); renderInventory();
  $("invEmpty").textContent = "Loading…"; S.limit.inst = 500; startProg(sc.label, $("hashes").checked);
  try {
    const { jobId } = await api("/api/inventory/start", { method: "POST", json: { scope: sc, hashes: $("hashes").checked, days: +$("days").value } });
    PROG.jobId = jobId;
    for (;;) {
      await new Promise((r) => setTimeout(r, 1200));
      const j = await api(`/api/inventory/${jobId}`);
      updProg(j.progress || {});
      if (j.status === "cancelled") { cancelled = true; break; }
      if (j.status === "done") { S.rows = j.rows; showWarnings(j.warnings); learned = j.learned; break; }
      if (j.status === "error") throw new Error(j.error);
    }
    $("invEmpty").textContent = cancelled ? "Cancelled - nothing was loaded." : S.rows.length ? "" : "No applications were reported for this scope.";
  } catch (e) { $("invEmpty").textContent = e.message; }
  finally {
    S.busy = false; $("fetch").disabled = false; endProg(); renderInventory();
    if (learned && (learned.new || learned.updated)) { await loadCatalog(true); toast(`Common applications learned ${learned.new} new and refreshed ${learned.updated} existing app(s) from this inventory.`, 6000); }
  }
};
function showWarnings(w) { const el = $("warnings"); if (w && w.length) { el.innerHTML = w.map(esc).join("<br>"); el.classList.remove("hidden"); } else el.classList.add("hidden"); }

function visibleRows() {
  const q = S.filter.toLowerCase(); if (!q) return S.rows;
  return S.rows.filter((r) => [r.name, r.publisher, r.hash, r.install_path, r.process].join(" ").toLowerCase().includes(q));
}
const alreadyIn = (row) => {
  const k = ruleKey({ "Rule Name": row.name, "Path": genPath(row.install_path), "Hash SHA-256": row.hash });
  return S.staged.has(row.id) || S.published.some((p) => ruleKey(p) === k);
};
const NOPUB = "(no publisher)";
const gKey = (tab, pub) => tab + "|" + pub;
function bodyHtml(tab, rows, rowFn, pubOf, idOf, canSel, cols) {
  const lim = S.limit[tab], more = (shown, all, unit) => all <= shown ? "" :
    `<tr class="more"><td colspan="${cols}">Showing ${shown.toLocaleString()} of ${all.toLocaleString()} ${unit} <button class="btn" data-more="${tab}">Show 500 more</button><button class="btn" data-more="${tab}" data-all="1">Show all</button></td></tr>`;
  if (!S.grouped) return rows.slice(0, lim).map((r) => rowFn(r, false)).join("") + more(Math.min(lim, rows.length), rows.length, "applications");
  const g = new Map();
  rows.forEach((r) => { const p = (pubOf(r) || "").trim() || NOPUB; (g.get(p) || g.set(p, []).get(p)).push(r); });
  const all = [...g.entries()].sort((a, b) => (a[0] === NOPUB) - (b[0] === NOPUB) || a[0].localeCompare(b[0]));
  return all.slice(0, Math.ceil(lim / 5)).map(([pub, list]) => {
    const sel = list.filter(canSel), n = sel.filter((r) => S.selected.has(idOf(r))).length;
    const open = S.open.has(gKey(tab, pub)) || !!S.filter;
    return `<tr class="grp ${open ? "open" : ""}" data-grow="${esc(gKey(tab, pub))}"><td class="c"><input type="checkbox" data-gp="${esc(gKey(tab, pub))}"
        ${sel.length && n === sel.length ? "checked" : ""} ${sel.length ? "" : "disabled"} data-ind="${n > 0 && n < sel.length ? 1 : 0}"></td>
      <td colspan="${cols - 1}"><span class="chev">&#9656;</span> ${esc(pub)} <span class="sub">${list.length} app${list.length > 1 ? "s" : ""}${n ? ` · ${n} selected` : ""}</span></td></tr>`
      + (open ? list.map((r) => rowFn(r, true)).join("") : "");
  }).join("") + more(Math.min(Math.ceil(lim / 5), all.length), all.length, "publishers");
}
function fixIndeterminate(tbl) { tbl.querySelectorAll("[data-ind='1']").forEach((c) => (c.indeterminate = true)); }
function groupItems(key) {
  const [tab, ...rest] = key.split("|"), pub = rest.join("|");
  const rows = tab === "com" ? visibleCommon() : visibleRows();
  const pubOf = tab === "com" ? (a) => a.publisher : (r) => r.publisher;
  return rows.filter((r) => ((pubOf(r) || "").trim() || NOPUB) === pub)
    .filter((r) => !alreadyIn(tab === "com" ? commonRow(r) : r)).map((r) => r.id);
}
function onGroupClick(e, rerender) {
  const mb = e.target.closest("[data-more]");
  if (mb) { S.limit[mb.dataset.more] = mb.dataset.all ? Infinity : S.limit[mb.dataset.more] + 500; rerender(); return; }
  const cb = e.target.closest("[data-gp]");
  if (cb) { const ids = groupItems(cb.dataset.gp); ids.forEach((id) => cb.checked ? S.selected.add(id) : S.selected.delete(id)); rerender(); return; }
  const row = e.target.closest("[data-grow]");
  if (row) { const k = row.dataset.grow; S.open.has(k) ? S.open.delete(k) : S.open.add(k); rerender(); }
}
function renderInventory() {
  const rows = visibleRows();
  $("invCount").textContent = S.rows.length.toLocaleString();
  const invRow = (r, kid) => {
    const inn = alreadyIn(r);
    return `<tr class="${kid ? "kid" : ""}"><td class="c"><input type="checkbox" data-id="${r.id}" ${S.selected.has(r.id) ? "checked" : ""} ${inn ? "disabled" : ""}></td>
      <td><b>${esc(r.name)}</b><div class="sub">${esc(r.version)}${r.endpoints ? ` · ${r.endpoints} endpoint${r.endpoints > 1 ? "s" : ""}` : ""} ${inn ? '<span class="tag in">in plan</span>' : ""}</div></td>
      <td>${esc(r.publisher)}</td><td class="mono">${esc(r.hash) || '<span class="sub">n/a</span>'}</td><td class="mono">${esc(r.install_path)}</td></tr>`;
  };
  $("invTable").querySelector("tbody").innerHTML = bodyHtml("inst", rows, invRow, (r) => r.publisher, (r) => r.id, (r) => !alreadyIn(r), 5);
  fixIndeterminate($("invTable"));
  $("invEmpty").classList.toggle("hidden", !!rows.length && !$("invEmpty").textContent);
  if (rows.length) $("invEmpty").classList.add("hidden");
  const selectable = rows.filter((r) => !alreadyIn(r));
  const nSel = selectable.filter((r) => S.selected.has(r.id)).length;
  $("selAll").checked = !!selectable.length && nSel === selectable.length;
  $("selAll").indeterminate = nSel > 0 && nSel < selectable.length;
  $("selInfo").textContent = rows.length ? `(${nSel} of ${selectable.length} selected)` : "";
  renderBar();
}
$("invTable").addEventListener("click", (e) => onGroupClick(e, renderInventory));
$("invTable").addEventListener("change", (e) => {
  const id = e.target.dataset.id; if (!id) return;
  e.target.checked ? S.selected.add(id) : S.selected.delete(id); renderInventory();
});
$("selAll").onchange = (e) => {
  visibleRows().filter((r) => !alreadyIn(r)).forEach((r) => e.target.checked ? S.selected.add(r.id) : S.selected.delete(r.id));
  renderInventory();
};
$("groupBy").onchange = (e) => { S.limit = { inst: 500, com: 500 }; S.grouped = e.target.checked; renderInventory(); renderCommon(); };
$("filter").oninput = (e) => { S.limit = { inst: 500, com: 500 }; S.filter = e.target.value; renderInventory(); renderCommon(); };

// ---------------- planning (staging) ----------------
$("addBtn").onclick = () => {
  const common = S.tab === "com";
  const src = common ? S.common.map((a) => ({ id: a.id, row: commonRow(a), name: a.name })) : S.rows.map((r) => ({ id: r.id, row: r, name: r.name }));
  let n = 0;
  src.filter((x) => S.selected.has(x.id) && !alreadyIn(x.row)).forEach((x) => { S.staged.set(x.id, { row: x.row, action: "ALLOW", name: x.name }); n++; });
  [...S.selected].forEach((id) => src.some((x) => x.id === id) && S.selected.delete(id));
  saveStaged(); setRTab("plan"); renderAll();
  toast(`${n} application${n === 1 ? "" : "s"} added to the plan (Allow). Nothing is published yet.`);
};
function saveStaged() { store.set("acui.staged", [...S.staged.entries()]); }
const summary = (r) => {
  if (r.install_path) return genPath(r.install_path);
  const bits = [r.publisher && "publisher " + r.publisher, r.process && "process " + r.process].filter(Boolean);
  return bits.join(" · ") || "no path";
};
function renderPlan() {
  const items = [...S.staged.entries()];
  $("planCount").textContent = items.length;
  $("planTable").querySelector("tbody").innerHTML = items.map(([id, it]) => `<tr class="${S.planSel.has(id) ? "picked" : ""}">
    <td class="c"><input type="checkbox" data-pid="${id}" ${S.planSel.has(id) ? "checked" : ""}></td>
    <td><input class="name" data-name="${id}" value="${esc(it.name)}">
      <div class="sub">${esc(summary(it.row))}${it.row.hash ? ` · ${esc(it.row.hash.slice(0, 12))}…` : ""}</div></td>
    <td><span class="seg">${["ALLOW", "BLOCK", "MONITOR"].map((a) => `<button data-seg="${id}" data-v="${a}" class="${it.action === a ? "on " + a : ""}">${a[0] + a.slice(1).toLowerCase()}</button>`).join("")}</span></td>
    <td class="c"><input type="checkbox" data-prop="${id}" title="Allow this application to spawn child processes (Allow rules only)" ${it.action !== "ALLOW" ? "disabled" : it.propagate === false ? "" : "checked"}></td></tr>`).join("");
  $("planEmpty").classList.toggle("hidden", items.length > 0);
  const nSel = [...S.planSel].filter((id) => S.staged.has(id)).length;
  $("planAll").checked = items.length > 0 && nSel === items.length;
  ["setAllow", "setBlock", "setMonitor", "unstage"].forEach((b) => ($(b).disabled = nSel === 0));
  renderBar();
}
$("planTable").addEventListener("change", (e) => {
  const t = e.target;
  if (t.dataset.pid) { t.checked ? S.planSel.add(t.dataset.pid) : S.planSel.delete(t.dataset.pid); renderPlan(); }
  if (t.dataset.prop) { S.staged.get(t.dataset.prop).propagate = t.checked; saveStaged(); }
  if (t.dataset.name) { S.staged.get(t.dataset.name).name = t.value.trim() || S.staged.get(t.dataset.name).row.name; saveStaged(); }
});
$("planTable").addEventListener("click", (e) => {
  const b = e.target.closest("[data-seg]"); if (!b) return;
  S.staged.get(b.dataset.seg).action = b.dataset.v; saveStaged(); renderPlan();
});
$("genPath").checked = S.gen;
$("genPath").onchange = (e) => { S.gen = e.target.checked; store.set("acui.gen", S.gen); renderAll(); };
$("planAll").onchange = (e) => { S.planSel = e.target.checked ? new Set(S.staged.keys()) : new Set(); renderPlan(); };
const bulk = (act) => { S.planSel.forEach((id) => S.staged.has(id) && (S.staged.get(id).action = act)); saveStaged(); renderPlan(); };
$("setAllow").onclick = () => bulk("ALLOW");
$("setBlock").onclick = () => bulk("BLOCK");
$("setMonitor").onclick = () => bulk("MONITOR");
$("unstage").onclick = () => { S.planSel.forEach((id) => S.staged.delete(id)); S.planSel.clear(); saveStaged(); renderAll(); };

// ---------------- publish ----------------
const toRule = (it) => {
  const r = it.row, ver = r.version ? ` ${r.version}` : "";
  return {
    "Rule Name": it.name, "Description": `${r.name}${ver}${r.endpoints ? ` - ${r.endpoints} endpoint(s)` : ""}`,
    "Rule Action": it.action, "OS Type": r.os || "WINDOWS", "Propagation": it.action !== "ALLOW" || it.propagate === false ? "false" : "true",
    "Publisher": r.publisher, "Path": genPath(r.install_path), "Binary Identity": "",
    "Hash SHA-256": r.hash, "Process": r.process, "Parent Process": r.parent,
  };
};
const matchSummary = (r) => [r.publisher && "Publisher " + r.publisher, r.install_path && "Path " + genPath(r.install_path), r.process && "Process " + r.process, r.hash && "Hash " + r.hash.slice(0, 12) + "…"].filter(Boolean).join(" · ") || "-";
$("publish").onclick = () => {
  const items = [...S.staged.values()]; if (!items.length) return;
  const cnt = (a) => items.filter((i) => i.action === a).length;
  const sc = currentScope(), site = S.siteName || (sc || {}).siteName || "";
  const base = (site.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 15).replace(/_+$/, "")) || "rules";
  $("rvFile").textContent = `Will be written to ${base}_${localStamp()}.csv and merged into the master rules file.`;
  $("rvStats").innerHTML = [["Total", items.length], ["Allow", cnt("ALLOW")], ["Block", cnt("BLOCK")], ["Monitor", cnt("MONITOR")]]
    .map(([k, v]) => `<div class="stat"><b>${v}</b>${k}</div>`).join("");
  const warn = [];
  const venderOnly = items.filter((i) => !i.row.install_path && !i.row.hash && !i.row.process);
  if (venderOnly.length) warn.push(`${venderOnly.length} rule(s) match on publisher only - they cover everything that publisher signs${venderOnly.some((i) => i.action === "BLOCK") ? ", including at least one BLOCK" : ""}.`);
  if (cnt("BLOCK")) warn.push(`${cnt("BLOCK")} BLOCK rule(s) will prevent matching applications from running once imported.`);
  const dupes = items.filter((i) => S.published.some((p) => ruleKey(p) === ruleKey(toRule(i)))).length;
  if (dupes) warn.push(`${dupes} rule(s) already exist in the master CSV and will be updated, not duplicated.`);
  const gen = items.filter((i) => genPath(i.row.install_path) !== i.row.install_path).length;
  if (gen) warn.push(`${gen} rule(s) use a wildcard user folder (e.g. C:\\Users\\*\\...) so they apply to every user profile, not just the one that was discovered.`);
  const noName = new Set(items.map((i) => i.name)); if (noName.size < items.length) warn.push("Some rules share the same Rule Name.");
  $("rvWarn").innerHTML = warn.map((w) => `<div class="rvw">${esc(w)}</div>`).join("");
  $("rvTable").querySelector("tbody").innerHTML = items.map((i) => `<tr><td><b>${esc(i.name)}</b></td>
    <td><span class="tag ${i.action}">${i.action}</span></td><td>${i.row.os === "MACOS" ? "macOS" : "Windows"}</td><td class="mono">${esc(matchSummary(i.row))}</td></tr>`).join("");
  $("review").showModal();
};
$("rvOk").onclick = (e) => { e.preventDefault(); $("review").close(); doPublish(); };
$("rvCancel").onclick = (e) => { e.preventDefault(); $("review").close(); };
async function doPublish() {
  const items = [...S.staged.values()]; if (!items.length) return;
  $("publish").disabled = true;
  try {
    const d = await api("/api/rules/publish", { method: "POST", json: { rules: items.map(toRule), siteName: S.siteName || (currentScope() || {}).siteName || "", stamp: localStamp() } });
    S.staged.clear(); S.planSel.clear(); saveStaged();
    await refreshPublished(); renderAll();
    showExport(d);
    toast(`Published ${d.added + d.updated} rule(s) to ${esc(d.export)}.`, 6000);
  } catch (e) { toast(esc(e.message), 8000); renderPlan(); }
  finally { renderBar(); }
}

function localStamp() {
  const d = new Date(), p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}`;
}
function showExport(d) {
  const el = $("lastExport");
  el.innerHTML = `<span><b>Published ${d.added + d.updated} rule(s)</b> (${d.added} new, ${d.updated} updated) &rarr; <b>${esc(d.export)}</b></span>
    <a class="btn primary" href="/api/rules/exports/${encodeURIComponent(d.export)}">Download ${esc(d.export)}</a>
    <a class="btn" href="/api/rules/download">Download all rules</a>`;
  el.classList.remove("hidden"); setRTab("plan"); refreshExports();
}
async function refreshExports() {
  try { S.exports = (await api("/api/rules/exports")).exports; } catch { S.exports = []; }
  $("expCount").textContent = S.exports.length;
  $("expTable").querySelector("tbody").innerHTML = S.exports.map((x) => `<tr><td class="mono">${esc(x.name)}</td><td>${x.rules}</td><td>${esc(x.modified)}</td>
    <td><a class="btn" href="/api/rules/exports/${encodeURIComponent(x.name)}">Download</a></td></tr>`).join("");
  $("expEmpty").classList.toggle("hidden", S.exports.length > 0);
}

// ---------------- published ----------------
async function refreshPublished() {
  try { const d = await api("/api/rules"); S.published = d.rules; $("pubFile").textContent = d.file; } catch (e) { toast(esc(e.message)); }
  renderPublished(); renderInventory();
}
function renderPublished() {
  $("pubCount").textContent = S.published.length;
  $("pubTable").querySelector("tbody").innerHTML = S.published.map((r) => `<tr>
    <td>${esc(r["Rule Name"])}</td><td><span class="tag ${esc(r["Rule Action"])}">${esc(r["Rule Action"])}</span></td>
    <td class="mono">${esc(r["Path"])}<div class="sub">${esc(r["Hash SHA-256"])}</div></td>
    <td><button class="btn ghost" data-del="${esc(ruleKey(r))}" title="Remove from CSV">✕</button></td></tr>`).join("");
  $("pubEmpty").classList.toggle("hidden", S.published.length > 0);
}
$("pubTable").addEventListener("click", async (e) => {
  const k = e.target.dataset.del; if (!k || !confirm("Remove this rule from the CSV?")) return;
  try { await api("/api/rules/delete", { method: "POST", json: { keys: [k] } }); await refreshPublished(); } catch (err) { toast(esc(err.message)); }
});
$("download").addEventListener("click", async (e) => {
  e.preventDefault();  // fetch with auth-free route, but keep a plain navigation fallback
  window.location.href = "/api/rules/download";
});
$("importFile").onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return;
  try {
    const d = await api("/api/rules/import", { method: "POST", body: await f.text(), headers: { "Content-Type": "text/csv" } });
    await refreshPublished(); toast(`Imported: ${d.added} added, ${d.updated} updated.`);
  } catch (err) { toast(esc(err.message), 8000); }
  e.target.value = "";
};

// ---------------- common applications ----------------
async function loadCatalog(noAuto) {
  try {
    const d = await api("/api/catalog"); S.common = d.apps;
    $("comUpdated").textContent = (d.updatedAt ? `last updated ${d.updatedAt}` : "not updated yet") + (d.learned ? ` · ${d.learned} learned` : "");
    $("comForget").disabled = !d.learned;
    const vs = [...new Set(S.common.map((a) => a.vendor))].sort((a, b) => a.localeCompare(b));
    $("comVendor").innerHTML = `<option value="">All vendors</option>` + vs.map((v) => `<option>${esc(v)}</option>`).join("");
    renderCommon();
    // refresh on page open, unless the cached data is newer than 12h (protects GitHub's anonymous rate limit)
    if (!noAuto && (d.ageHours === null || d.ageHours > 12)) runCatalogUpdate(S.common.filter((a) => a.updatable).map((a) => a.id));
  } catch (e) { toast(esc(e.message)); }
}
function visibleCommon() {
  const q = S.filter.toLowerCase(), os = S.osFilter, v = $("comVendor").value, k = $("comKind").value;
  return S.common.filter((r) => (!os || r.os === os) && (!v || r.vendor === v) && (!k || (k === "learned" ? r.trust === "learned" : r.kind === k)) &&
    (!q || [r.name, r.vendor, r.publisher, r.version, r.install_path].join(" ").toLowerCase().includes(q)));
}
const commonRow = (a) => ({ id: a.id, name: a.name, publisher: a.publisher, version: a.kind === "vendor" ? "" : a.version,
  install_path: a.install_path, process: a.process, hash: a.hash || "", os: a.os, endpoints: 0, signer: "", parent: "" });
const updTargets = () => {
  const sel = S.common.filter((a) => a.updatable && S.selected.has(a.id));
  return sel.length ? { ids: sel.map((a) => a.id), label: `Update selected (${sel.length})` }
                    : (() => { const v = visibleCommon().filter((a) => a.updatable); return { ids: v.map((a) => a.id), label: `Update shown (${v.length})` }; })();
};
function renderCommon() {
  const rows = visibleCommon();
  $("comCount").textContent = S.common.length.toLocaleString(); $("comCount").title = `${S.common.filter((a) => a.trust !== "learned").length} built-in + ${S.common.filter((a) => a.trust === "learned").length} learned from your inventory`;
  const comRow = (a, kid) => {
    const inn = alreadyIn(commonRow(a)), vend = a.kind === "vendor";
    const trust = a.trust === "learned" ? `<span class="tag learned" title="Learned from your inventory${a.last_seen ? " - last seen " + esc(a.last_seen) : ""}${a.seen_in && a.seen_in.length ? " in " + esc(a.seen_in.join(", ")) : ""}">learned</span>`
                : a.trust === "export" ? '<span class="tag in" title="Seen in your console rules export or process telemetry">in your console</span>'
                                       : '<span class="tag verify" title="From public knowledge - confirm against your own apps">verify</span>';
    const dash = '<span class="sub">-</span>';
    return `<tr class="${kid ? "kid" : ""}"><td class="c"><input type="checkbox" data-cid="${a.id}" ${S.selected.has(a.id) ? "checked" : ""} ${inn ? "disabled" : ""}></td>
      <td><b>${esc(a.name)}</b><div class="sub">${vend ? "whole-vendor rule" : esc(a.process)} ${trust} ${inn ? '<span class="tag in">in plan</span>' : ""}${a.status === "update failed" ? `<span class="tag fail" title="${esc(a.error)}">update failed</span>` : ""}</div></td>
      <td>${a.os === "MACOS" ? "macOS" : "Windows"}</td><td>${esc(a.publisher) || dash}</td>
      <td>${vend ? dash : (esc(a.version) || (a.updatable ? dash : (a.trust === "learned" ? dash : '<span class="sub">no public feed</span>')))}</td>
      <td class="mono">${vend ? dash : (esc(a.installer_sha256 || a.hash) || dash)}</td>
      <td class="mono">${vend ? '<span class="sub">any (publisher rule)</span>' : (esc(a.install_path) || '<span class="sub">per-user install</span>')}</td></tr>`;
  };
  $("comTable").querySelector("tbody").innerHTML = bodyHtml("com", rows, comRow, (a) => a.publisher, (a) => a.id, (a) => !alreadyIn(commonRow(a)), 7);
  fixIndeterminate($("comTable"));
  const sel = rows.filter((a) => !alreadyIn(commonRow(a)));
  const n = sel.filter((a) => S.selected.has(a.id)).length;
  $("selAllC").checked = !!sel.length && n === sel.length; $("selAllC").indeterminate = n > 0 && n < sel.length;
  $("selInfoC").textContent = `(${n} of ${sel.length} selected)`; renderBar();
  $("comUpdate").textContent = updTargets().label;
}
$("comTable").addEventListener("click", (e) => onGroupClick(e, renderCommon));
$("comTable").addEventListener("change", (e) => {
  const id = e.target.dataset.cid; if (!id) return;
  e.target.checked ? S.selected.add(id) : S.selected.delete(id); renderCommon();
});
$("selAllC").onchange = (e) => {
  visibleCommon().filter((a) => !alreadyIn(commonRow(a))).forEach((a) => e.target.checked ? S.selected.add(a.id) : S.selected.delete(a.id));
  renderCommon();
};
["comVendor", "comKind"].forEach((id) => ($(id).onchange = () => { S.limit.com = 500; renderCommon(); }));
$("osChips").addEventListener("click", (e) => {
  const b = e.target.closest("[data-os]"); if (!b) return; S.osFilter = b.dataset.os; S.limit.com = 500;
  $("osChips").querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c === b)); renderCommon();
});
async function runCatalogUpdate(allIds) {
  const t = Array.isArray(allIds) ? { ids: allIds } : updTargets(); if (!t.ids.length) { toast("Nothing to update - the rows shown have no public version feed."); return; }
  const b = $("comUpdate"); b.disabled = true; $("comProgress").classList.remove("hidden");
  try {
    const { jobId } = await api("/api/catalog/update", { method: "POST", json: { ids: t.ids } });
    for (;;) {
      await new Promise((r) => setTimeout(r, 1000));
      const j = await api(`/api/inventory/${jobId}`), p = j.progress || {};
      $("comProgText").textContent = `${p.stage || ""}${p.total ? ` (${p.done}/${p.total})` : ""}`;
      $("comBar").style.width = p.total ? Math.round(100 * p.done / p.total) + "%" : "0";
      if (j.status === "done") { S.common = j.rows; if (j.warnings && j.warnings.length) toast(esc(j.warnings.join(" ")), 9000); break; }
      if (j.status === "error") throw new Error(j.error);
    }
    await loadCatalogLabel();
  } catch (e) { toast(esc(e.message), 8000); }
  finally { b.disabled = false; $("comProgress").classList.add("hidden"); renderCommon(); }
}
async function loadCatalogLabel() { const d = await api("/api/catalog"); $("comUpdated").textContent = d.updatedAt ? `last updated ${d.updatedAt}` : ""; }
$("comForget").onclick = async () => {
  const sel = S.common.filter((a) => a.trust === "learned" && S.selected.has(a.id)).map((a) => a.id);
  const msg = sel.length ? `Forget ${sel.length} selected learned application(s)?` : "Forget ALL applications learned from inventory fetches? (Built-in entries are not affected.)";
  if (!confirm(msg)) return;
  try { const d = await api("/api/catalog/forget", { method: "POST", json: sel.length ? { ids: sel } : { all: true } });
    sel.forEach((id) => S.selected.delete(id)); await loadCatalog(true); toast(`Forgot ${d.removed} learned application(s).`); } catch (e) { toast(esc(e.message)); }
};
$("aboutBtn").onclick = () => $("about").showModal();
$("aboutLink").onclick = (e) => { e.preventDefault(); $("about").showModal(); };
$("comUpdate").onclick = () => runCatalogUpdate();   // button: selected rows, or all shown

function setTab(t) {
  S.tab = t; $("tabInst").classList.toggle("active", t === "inst"); $("tabCom").classList.toggle("active", t === "com");
  $("paneInst").classList.toggle("hidden", t !== "inst"); $("paneCom").classList.toggle("hidden", t !== "com");
  $("filter").placeholder = t === "inst" ? "Filter name, publisher, hash, path…" : "Filter name, vendor, publisher, version…";
  renderBar();
}
function setRTab(t) {
  S.rtab = t;
  [["plan", "Plan"], ["pub", "Pub"], ["exp", "Exp"]].forEach(([k, n]) => {
    $("tab" + n).classList.toggle("active", t === k); $("pane" + n).classList.toggle("hidden", t !== k);
  });
}
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => b.dataset.side === "left" ? setTab(b.dataset.tab === "com" ? "com" : "inst") : setRTab(b.dataset.tab)));
function renderBar() {
  const ids = new Set((S.tab === "com" ? S.common : S.rows).map((x) => x.id));
  const n = [...S.selected].filter((id) => ids.has(id)).length;
  $("barSel").textContent = `${n} selected`;
  $("barWhere").textContent = S.tab === "com" ? "in Common applications" : "in Installed on endpoints";
  $("addBtn").disabled = n === 0;
  const items = [...S.staged.values()], blocks = items.filter((i) => i.action === "BLOCK").length;
  $("barPlan").textContent = `Plan: ${items.length} rule${items.length === 1 ? "" : "s"}${blocks ? ` · ${blocks} block` : ""}`;
  $("publish").disabled = items.length === 0;
  $("publish").textContent = items.length ? `Publish ${items.length} rule${items.length > 1 ? "s" : ""}` : "Publish to CSV";
}
function renderAll() { renderInventory(); renderPlan(); renderPublished(); renderCommon(); }

// ---------------- boot ----------------
(async () => {
  S.url = sess.get("url"); S.token = sess.get("token");
  if (S.url && S.token) { try { enterApp(await api("/api/login", { method: "POST", json: {} })); return; } catch { S.token = ""; } }
  showLogin();
})();
})();
