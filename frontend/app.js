"use strict";

const state = { view: "catalog", exercise: null, range: null };
const session = { token: null, username: null, role: null, display: null, permissions: [] };

const TOKEN_KEY = "cr_token";

function can(permission) { return session.permissions.includes(permission); }

async function api(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  if (session.token) headers["Authorization"] = "Bearer " + session.token;
  const opts = { method, headers };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch("/api" + path, opts);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && session.token) {
    // Session expired or revoked — force re-login.
    clearSession();
    showLogin("Your session expired. Please sign in again.");
    throw new Error(data.error || "session expired");
  }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function toast(msg, kind = "ok") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = `toast show ${kind}`;
  setTimeout(() => { el.className = "toast"; }, 3200);
}

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

const $main = () => document.getElementById("main");

// ---------------- Catalog view ----------------
async function viewCatalog() {
  const m = $main();
  m.innerHTML = `
    <div class="toolbar">
      <input id="q" placeholder="Search scenarios…" />
      <select id="f-diff"><option value="">Any difficulty</option>
        <option>intermediate</option><option>advanced</option></select>
      <select id="f-plat"><option value="">Any platform</option>
        <option>windows</option><option>linux</option><option>docker</option></select>
      <button class="ghost" id="btn-search">Filter</button>
    </div>
    <h3>Scenarios</h3><div class="grid" id="scenarios"></div>
    <h3>TTP behavior modules</h3>
    <div class="toolbar">
      <select id="m-plat"><option value="">Any platform</option>
        <option>windows</option><option>linux</option><option>docker</option></select>
      <select id="m-safe"><option value="">Any safety class</option>
        <option>S0</option><option>S1</option><option>S2</option></select>
      <button class="ghost" id="btn-msearch">Filter modules</button>
    </div>
    <div class="grid" id="modules"></div>`;

  async function loadScenarios() {
    const p = new URLSearchParams();
    const q = document.getElementById("q").value;
    const diff = document.getElementById("f-diff").value;
    const plat = document.getElementById("f-plat").value;
    if (q) p.set("q", q);
    if (diff) p.set("difficulty", diff);
    if (plat) p.set("platform", plat);
    const scenarios = await api("GET", "/scenarios?" + p.toString());
    const wrap = document.getElementById("scenarios");
    wrap.innerHTML = "";
    scenarios.forEach((s) => wrap.appendChild(scenarioCard(s)));
    if (!scenarios.length) wrap.innerHTML = `<p class="muted">No scenarios match.</p>`;
  }

  async function loadModules() {
    const p = new URLSearchParams();
    const plat = document.getElementById("m-plat").value;
    const safe = document.getElementById("m-safe").value;
    if (plat) p.set("platform", plat);
    if (safe) p.set("safety_class", safe);
    const mods = await api("GET", "/modules?" + p.toString());
    const wrap = document.getElementById("modules");
    wrap.innerHTML = "";
    mods.forEach((mm) => wrap.appendChild(moduleCard(mm)));
  }

  document.getElementById("btn-search").onclick = loadScenarios;
  document.getElementById("btn-msearch").onclick = loadModules;
  await loadScenarios();
  await loadModules();
}

function scenarioCard(s) {
  const techs = (s.technique_ids || []).map((t) => `<span class="tag tech">${t}</span>`).join(" ");
  const dur = (s.duration_min || []).join("–");
  return el(`<div class="card">
    <div class="row" style="justify-content:space-between">
      <h4>${esc(s.name)}</h4><span class="tag">${esc(s.mode)}</span>
    </div>
    <p class="mono muted">${esc(s.id)} · ${esc(s.difficulty)} · ${dur} min</p>
    <p>${esc(s.team_objective)}</p>
    <div class="row">${techs}</div>
    <div class="row" style="margin-top:12px">
      <button class="act" data-launch="${esc(s.id)}">Launch range</button>
    </div>
  </div>`);
}

function moduleCard(m) {
  const sc = (m.safety_class || "").toLowerCase();
  const techs = (m.technique_ids || []).map((t) => `<span class="tag tech">${t}</span>`).join(" ");
  return el(`<div class="card">
    <div class="row" style="justify-content:space-between">
      <h4>${esc(m.name)}</h4>
      <span class="tag ${sc}">${esc(m.safety_class)}</span>
    </div>
    <p class="mono muted">${esc(m.id)} · <span class="tag ${esc(m.platform)}">${esc(m.platform)}</span></p>
    <div class="row">${techs}</div>
    <p>${esc(m.detection_notes || "")}</p>
    <p class="muted">Cleanup: ${esc(m.cleanup || "—")}</p>
  </div>`);
}

// ---------------- Ranges view ----------------
async function viewRanges() {
  const m = $main();
  m.innerHTML = `<h2>Ranges</h2>
    <div class="toolbar">
      <select id="new-scenario"></select>
      <button class="act" id="btn-create">Create range</button>
      <button class="ghost" id="btn-refresh">Refresh</button>
    </div>
    <table><thead><tr><th>ID</th><th>Scenario</th><th>State</th><th>Expiry</th><th>Actions</th></tr></thead>
    <tbody id="range-rows"></tbody></table>`;

  const scenarios = await api("GET", "/scenarios");
  const sel = document.getElementById("new-scenario");
  scenarios.forEach((s) => sel.appendChild(el(`<option value="${esc(s.id)}">${esc(s.name)}</option>`)));

  document.getElementById("btn-create").onclick = async () => {
    try {
      const r = await api("POST", "/ranges", { scenario_id: sel.value });
      toast(`Created ${r.id}`);
      await loadRanges();
    } catch (e) { toast(e.message, "err"); }
  };
  document.getElementById("btn-refresh").onclick = loadRanges;
  await loadRanges();
}

const NEXT_ACTION = {
  REQUESTED: "preflight", PREFLIGHT: "provision", PROVISIONING: "seed",
  SEEDING: "ready", READY: "start",
};

async function loadRanges() {
  const ranges = await api("GET", "/ranges");
  const tb = document.getElementById("range-rows");
  tb.innerHTML = "";
  ranges.forEach((r) => {
    const next = NEXT_ACTION[r.state];
    const row = el(`<tr>
      <td class="mono">${esc(r.id)}</td>
      <td>${esc(r.scenario_id)}</td>
      <td><span class="badge state ${esc(r.state)}">${esc(r.state)}</span></td>
      <td class="mono muted">${esc((r.expiry_at || "").slice(0, 16))}</td>
      <td class="row"></td></tr>`);
    const actions = row.querySelector("td.row");
    if (next && next !== "start") {
      const b = el(`<button class="ghost">→ ${next}</button>`);
      b.onclick = () => advance(r.id, next);
      actions.appendChild(b);
    }
    if (r.state === "READY") {
      const b = el(`<button class="act">Start exercise</button>`);
      b.onclick = () => startExercise(r.id);
      actions.appendChild(b);
    }
    if (!["DESTROYED", "ARCHIVED"].includes(r.state)) {
      const q = el(`<button class="ghost">Quarantine</button>`);
      q.onclick = () => advance(r.id, "quarantine");
      actions.appendChild(q);
    }
    tb.appendChild(row);
  });
  if (!ranges.length) tb.innerHTML = `<tr><td colspan="5" class="muted">No ranges yet.</td></tr>`;
}

async function advance(rid, action) {
  try {
    const r = await api("POST", `/ranges/${rid}/actions`, { action });
    toast(`${rid} → ${r.state}`);
    await loadRanges();
  } catch (e) { toast(e.message, "err"); }
}

async function startExercise(rid) {
  try {
    const ex = await api("POST", "/exercises", { range_id: rid });
    state.exercise = ex.id;
    toast(`Exercise ${ex.id} started`);
    switchView("exercise");
  } catch (e) { toast(e.message, "err"); }
}

// ---------------- Exercise view ----------------
async function viewExercise() {
  const m = $main();
  const exercises = await api("GET", "/exercises");
  if (!exercises.length) {
    m.innerHTML = `<h2>Exercise</h2><p class="muted">No exercises yet. Create a range and start one.</p>`;
    return;
  }
  if (!state.exercise) state.exercise = exercises[0].id;

  m.innerHTML = `<div class="toolbar">
      <select id="ex-select"></select>
      <button class="ghost" id="btn-report">Report</button>
      <button class="ghost" id="btn-end">End exercise</button>
    </div>
    <div class="split">
      <div>
        <div class="card" id="ex-meta"></div>
        <h3>Run a TTP module</h3>
        <div class="card">
          <div class="row">
            <select id="mod-select" style="flex:1"></select>
            <button class="act" id="btn-run-mod">Execute</button>
          </div>
          <p class="muted" style="font-size:12px">S2 modules require instructor/admin role.</p>
        </div>
        <h3>Instructor inject</h3>
        <div class="card">
          <div class="row"><input id="inject-text" placeholder="Inject text…" style="flex:1" />
          <button class="ghost" id="btn-inject">Inject</button></div>
        </div>
        <h3>Blue: submit evidence</h3>
        <div class="card">
          <div class="row"><input id="ev-text" placeholder="Evidence description…" style="flex:1" />
          <button class="ghost" id="btn-ev">Submit</button></div>
        </div>
        <h3>Detection result</h3>
        <div class="card">
          <div class="row">
            <input id="det-tech" placeholder="T1059" style="width:90px" />
            <select id="det-verdict"><option>detected</option><option>missed</option><option>false_positive</option></select>
            <button class="ghost" id="btn-det">Record</button>
          </div>
        </div>
        <h3>Score</h3>
        <div class="card" id="score-panel"></div>
      </div>
      <div>
        <h3>Synchronized timeline (UTC)</h3>
        <ul class="timeline" id="timeline"></ul>
      </div>
    </div>`;

  const sel = document.getElementById("ex-select");
  exercises.forEach((e) =>
    sel.appendChild(el(`<option value="${esc(e.id)}" ${e.id === state.exercise ? "selected" : ""}>${esc(e.id)} · ${esc(e.status)}</option>`)));
  sel.onchange = () => { state.exercise = sel.value; viewExercise(); };

  const scenario = await loadExerciseMeta();
  await loadModuleSelect(scenario);
  buildScorePanel();
  await loadTimeline();

  document.getElementById("btn-run-mod").onclick = runModule;
  document.getElementById("btn-inject").onclick = doInject;
  document.getElementById("btn-ev").onclick = doEvidence;
  document.getElementById("btn-det").onclick = doDetection;
  document.getElementById("btn-report").onclick = showReport;
  document.getElementById("btn-end").onclick = endExercise;
}

async function loadExerciseMeta() {
  const ex = await api("GET", `/exercises/${state.exercise}`);
  state.range = ex.range_id;
  const scenario = await api("GET", `/scenarios/${ex.scenario_id}`);
  document.getElementById("ex-meta").innerHTML = `
    <div class="row" style="justify-content:space-between">
      <h4>${esc(scenario.name)}</h4>
      <span class="badge state">${esc(ex.status)}</span>
    </div>
    <p class="mono muted">${esc(ex.id)}</p>
    <p>${esc(scenario.team_objective)}</p>
    <div class="kv">
      <dt>Objectives</dt><dd>${(scenario.objectives || []).map(o => `${o.role}:${o.points}`).join(" · ")}</dd>
      <dt>Techniques</dt><dd>${(scenario.technique_ids || []).join(", ")}</dd>
    </div>`;
  return scenario;
}

async function loadModuleSelect(scenario) {
  const mods = await api("GET", "/modules");
  const inScenario = new Set(scenario.module_ids || []);
  const sel = document.getElementById("mod-select");
  sel.innerHTML = "";
  mods.sort((a, b) => (inScenario.has(b.id) ? 1 : 0) - (inScenario.has(a.id) ? 1 : 0));
  mods.forEach((mm) => {
    const star = inScenario.has(mm.id) ? "★ " : "";
    sel.appendChild(el(`<option value="${esc(mm.id)}">${star}${esc(mm.name)} [${esc(mm.safety_class)}/${esc(mm.platform)}]</option>`));
  });
}

async function runModule() {
  try {
    const mid = document.getElementById("mod-select").value;
    const res = await api("POST", `/exercises/${state.exercise}/modules`, { module_id: mid });
    toast(`Executed ${res.executed} → ${res.techniques.join(", ")}`);
    await loadTimeline();
  } catch (e) { toast(e.message, "err"); }
}

async function doInject() {
  try {
    const text = document.getElementById("inject-text").value;
    if (!text) return;
    await api("POST", `/exercises/${state.exercise}/injects`, { text });
    document.getElementById("inject-text").value = "";
    toast("Inject published");
    await loadTimeline();
  } catch (e) { toast(e.message, "err"); }
}

async function doEvidence() {
  try {
    const description = document.getElementById("ev-text").value;
    if (!description) return;
    const r = await api("POST", `/exercises/${state.exercise}/evidence`, { description });
    document.getElementById("ev-text").value = "";
    toast(`Evidence ${r.id} (hash ${r.integrity_hash.slice(0, 10)}…)`);
    await loadTimeline();
  } catch (e) { toast(e.message, "err"); }
}

async function doDetection() {
  try {
    const technique_id = document.getElementById("det-tech").value || "T1059";
    const verdict = document.getElementById("det-verdict").value;
    await api("POST", `/exercises/${state.exercise}/detections`,
      { technique_id, verdict, rule_version: "v1", latency_s: 30 });
    toast(`Detection recorded: ${technique_id} ${verdict}`);
    await loadTimeline();
  } catch (e) { toast(e.message, "err"); }
}

const DIMS = ["red_execution", "detection", "investigation", "response", "collaboration"];
function buildScorePanel() {
  const p = document.getElementById("score-panel");
  p.innerHTML = DIMS.map((d) =>
    `<div class="row" style="justify-content:space-between;margin-bottom:6px">
      <label style="color:var(--muted)">${d}</label>
      <input type="range" min="0" max="100" value="70" id="sc-${d}" style="flex:1;margin:0 10px" />
      <span class="mono" id="scv-${d}">70</span></div>`
  ).join("") +
    `<button class="act" id="btn-score" style="margin-top:8px">Compute score</button>
     <div id="score-out" style="margin-top:12px"></div>`;
  DIMS.forEach((d) => {
    const r = document.getElementById(`sc-${d}`);
    r.oninput = () => { document.getElementById(`scv-${d}`).textContent = r.value; };
  });
  document.getElementById("btn-score").onclick = computeScore;
}

async function computeScore() {
  try {
    const raw = {};
    DIMS.forEach((d) => { raw[d] = Number(document.getElementById(`sc-${d}`).value); });
    const res = await api("POST", `/exercises/${state.exercise}/score`, { raw_scores: raw });
    const bars = res.dimensions.map((d) =>
      `<div style="margin:6px 0"><div class="row" style="justify-content:space-between">
        <span class="muted">${d.dimension} (×${d.weight})</span><span class="mono">${d.contribution}</span></div>
       <div class="bar"><span style="width:${d.raw}%"></span></div></div>`).join("");
    document.getElementById("score-out").innerHTML =
      `<div class="row" style="justify-content:space-between"><h4>Total: ${res.total}</h4>
       <span class="muted">weighted ${res.weighted_before_penalty}</span></div>${bars}`;
    toast(`Score ${res.total}`);
  } catch (e) { toast(e.message, "err"); }
}

async function loadTimeline() {
  const events = await api("GET", `/exercises/${state.exercise}/timeline`);
  const ul = document.getElementById("timeline");
  ul.innerHTML = "";
  events.slice().reverse().forEach((ev) => {
    const tech = ev.technique_id ? `<span class="tag tech">${esc(ev.technique_id)}</span>` : "";
    ul.appendChild(el(`<li>
      <div class="ts">${esc(ev.ts_utc.slice(11, 23))} · ${esc(ev.source)}</div>
      <div><span class="kind">${esc(ev.kind)}</span> ${tech}
        <span class="muted">— ${esc(ev.actor || "")}</span></div>
    </li>`));
  });
  if (!events.length) ul.innerHTML = `<li class="muted">No events yet.</li>`;
}

async function endExercise() {
  try {
    await api("POST", `/exercises/${state.exercise}/end`, {});
    toast("Exercise ended, evidence locked");
    await viewExercise();
  } catch (e) { toast(e.message, "err"); }
}

async function showReport() {
  try {
    const rep = await api("GET", `/exercises/${state.exercise}/report`);
    const m = $main();
    const cov = rep.coverage;
    m.innerHTML = `<div class="toolbar"><button class="ghost" id="back">← Back</button>
      <h2 style="margin:0">After-action report</h2></div>
      <div class="card"><h4>${esc(rep.scenario.name)} · ${esc(rep.scenario.mode)}</h4>
        <p class="mono muted">${esc(rep.exercise_id)} · ${esc(rep.status)}</p>
        <div class="kv">
          <dt>Expected techniques</dt><dd>${(cov.expected || []).join(", ") || "—"}</dd>
          <dt>Observed</dt><dd>${(cov.observed || []).join(", ") || "—"}</dd>
          <dt>Detected</dt><dd>${(cov.detected || []).join(", ") || "—"}</dd>
          <dt>Coverage gaps</dt><dd style="color:var(--red)">${(cov.gaps || []).join(", ") || "none"}</dd>
          <dt>Timeline events</dt><dd>${rep.timeline_events}</dd>
          <dt>Evidence items</dt><dd>${rep.evidence_count}</dd>
          <dt>Score</dt><dd>${rep.score ? rep.score.total : "not scored"}</dd>
        </div></div>
      <h3>Recommendations</h3>
      <div class="card"><ul>${(rep.recommendations || []).map(r => `<li>${esc(r)}</li>`).join("")}</ul></div>
      <h3>Raw report JSON</h3><pre>${esc(JSON.stringify(rep, null, 2))}</pre>`;
    document.getElementById("back").onclick = () => switchView("exercise");
  } catch (e) { toast(e.message, "err"); }
}

// ---------------- Reference view ----------------
async function viewReference() {
  const m = $main();
  const [ref, tactics, topos, roles] = await Promise.all([
    api("GET", "/reference"), api("GET", "/tactics"), api("GET", "/topologies"),
    api("GET", "/roles"),
  ]);
  m.innerHTML = `<h2>Reference</h2>
    <h3>Roles &amp; permissions — what each role can do</h3>
    <div class="role-matrix">${roles.map(r => `<div class="card">
      <div class="row" style="justify-content:space-between">
        <h4>${esc(r.role)}</h4>
        <span class="tag">${r.permissions.length} permissions</span></div>
      <p>${esc(r.summary)}</p>
      <div class="perm-list">${r.capabilities.map(c => `<span class="tag">${esc(c)}</span>`).join("")}</div>
    </div>`).join("")}</div>
    <h3>ATT&CK coverage (${tactics.length} techniques)</h3>
    <table><thead><tr><th>Tactic</th><th>ATT&CK</th><th>Lab behavior</th><th>Expected evidence</th></tr></thead>
      <tbody>${tactics.map(t => `<tr><td>${esc(t.tactic)}</td><td class="mono">${esc(t.attack)}</td>
        <td>${esc(t.lab_behavior)}</td><td class="muted">${esc(t.expected_evidence)}</td></tr>`).join("")}</tbody></table>
    <h3>Scoring dimensions</h3>
    <table><thead><tr><th>Dimension</th><th>Weight</th><th>Metrics</th></tr></thead>
      <tbody>${ref.scoring_dimensions.map(d => `<tr><td>${esc(d.label)}</td>
        <td class="mono">${(d.weight * 100).toFixed(0)}%</td><td class="muted">${esc(d.metrics)}</td></tr>`).join("")}</tbody></table>
    <h3>Module safety classes</h3>
    <table><thead><tr><th>Class</th><th>Name</th><th>Description</th><th>Approval</th></tr></thead>
      <tbody>${ref.safety_classes.map(s => `<tr><td class="mono">${esc(s.class)}</td><td>${esc(s.name)}</td>
        <td class="muted">${esc(s.description)}</td><td>${esc(s.approval)}</td></tr>`).join("")}</tbody></table>
    <h3>Detection stack (MVP)</h3>
    <table><thead><tr><th>Layer</th><th>Choice</th></tr></thead>
      <tbody>${ref.detection_stack.map(s => `<tr><td>${esc(s.layer)}</td><td class="muted">${esc(s.choice)}</td></tr>`).join("")}</tbody></table>
    <h3>Topology templates</h3>
    <div class="grid">${topos.map(t => `<div class="card"><h4>${esc(t.name)}</h4>
      <p class="mono muted">${esc(t.id)} · egress ${esc(t.egress)}</p><p>${esc(t.description)}</p>
      <p class="muted">VMs: ${t.vms.map(v => v.name).join(", ")}</p></div>`).join("")}</div>
    <h3>Lifecycle states</h3>
    <p class="mono">${ref.lifecycle_states.join("  →  ")}</p>`;
}

// ---------------- Audit view ----------------
async function viewAudit() {
  const m = $main();
  const log = await api("GET", "/audit?limit=200");
  m.innerHTML = `<h2>Audit ledger</h2>
    <table><thead><tr><th>Time (UTC)</th><th>Actor</th><th>Role</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
    <tbody>${log.map(a => `<tr><td class="mono muted">${esc((a.ts_utc || "").slice(11, 23))}</td>
      <td>${esc(a.actor)}</td><td><span class="tag">${esc(a.role)}</span></td>
      <td class="mono">${esc(a.action)}</td><td class="mono muted">${esc(a.target)}</td>
      <td class="muted">${esc(a.detail || "")}</td></tr>`).join("")}</tbody></table>
    ${log.length ? "" : '<p class="muted">No audit entries yet.</p>'}`;
}

// ---------------- Admin panel (user provisioning) ----------------
const ROLE_OPTS = ["red", "blue", "purple", "instructor", "solo", "security_leader", "admin"];

async function viewAdmin() {
  const m = $main();
  if (!can("admin:manage_users")) {
    m.innerHTML = `<h2>Admin</h2><p class="muted">Your role (${esc(session.role)}) cannot manage users.</p>`;
    return;
  }
  m.innerHTML = `<h2>Admin · user provisioning</h2>
    <div class="split">
      <div>
        <h3>Provision a user</h3>
        <div class="card">
          <label class="lbl">Username<input id="nu-user" placeholder="e.g. red-op-2" /></label>
          <label class="lbl" style="margin-top:8px">Display name<input id="nu-name" placeholder="Optional" /></label>
          <label class="lbl" style="margin-top:8px">Role
            <select id="nu-role">${ROLE_OPTS.map(r => `<option value="${r}">${r}</option>`).join("")}</select></label>
          <label class="lbl" style="margin-top:8px">Password<input id="nu-pass" type="password" placeholder="min 4 chars" /></label>
          <button class="act" id="btn-create-user" style="margin-top:12px;width:100%">Create user</button>
        </div>
      </div>
      <div>
        <h3>Provisioned users</h3>
        <table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Created by</th><th></th></tr></thead>
        <tbody id="user-rows"></tbody></table>
      </div>
    </div>`;

  document.getElementById("btn-create-user").onclick = async () => {
    try {
      const body = {
        username: document.getElementById("nu-user").value.trim(),
        display_name: document.getElementById("nu-name").value.trim() || undefined,
        role: document.getElementById("nu-role").value,
        password: document.getElementById("nu-pass").value,
      };
      const u = await api("POST", "/users", body);
      toast(`Provisioned ${u.username} (${u.role})`);
      await loadUsers();
      document.getElementById("nu-user").value = "";
      document.getElementById("nu-name").value = "";
      document.getElementById("nu-pass").value = "";
    } catch (e) { toast(e.message, "err"); }
  };
  await loadUsers();
}

async function loadUsers() {
  const users = await api("GET", "/users");
  const tb = document.getElementById("user-rows");
  tb.innerHTML = "";
  users.forEach((u) => {
    const row = el(`<tr>
      <td><strong>${esc(u.username)}</strong><br><span class="muted">${esc(u.display_name || "")}</span></td>
      <td><span class="tag">${esc(u.role)}</span></td>
      <td>${u.active ? '<span class="tag s0">active</span>' : '<span class="tag s2">disabled</span>'}</td>
      <td class="muted mono">${esc(u.created_by || "")}</td>
      <td></td></tr>`);
    const cell = row.querySelector("td:last-child");
    if (u.username !== session.username) {
      const b = el(`<button class="ghost">${u.active ? "Disable" : "Enable"}</button>`);
      b.onclick = async () => {
        try {
          await api("POST", `/users/${encodeURIComponent(u.username)}/active`, { active: !u.active });
          toast(`${u.username} ${u.active ? "disabled" : "enabled"}`);
          await loadUsers();
        } catch (e) { toast(e.message, "err"); }
      };
      cell.appendChild(b);
    } else {
      cell.innerHTML = '<span class="muted">you</span>';
    }
    tb.appendChild(row);
  });
}

// ---------------- Router ----------------
const VIEWS = {
  catalog: viewCatalog, ranges: viewRanges, exercise: viewExercise,
  reference: viewReference, audit: viewAudit, admin: viewAdmin,
};

function switchView(name) {
  state.view = name;
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.view === name));
  VIEWS[name]().catch((e) => { $main().innerHTML = `<p class="muted">Error: ${esc(e.message)}</p>`; });
}

async function checkHealth() {
  const pill = document.getElementById("health");
  try {
    await api("GET", "/health");
    pill.textContent = "● online"; pill.className = "pill ok";
  } catch {
    pill.textContent = "● offline"; pill.className = "pill bad";
  }
}

// ---------------- Session / login ----------------
function applySession(s) {
  session.token = s.token || session.token;
  session.username = s.username;
  session.role = s.role;
  session.display = s.display_name || s.username;
  session.permissions = s.permissions || [];
  if (session.token) localStorage.setItem(TOKEN_KEY, session.token);
  document.getElementById("who-name").textContent = session.display;
  const roleTag = document.getElementById("who-role");
  roleTag.textContent = session.role;
  document.getElementById("tab-admin").hidden = !can("admin:manage_users");
}

function clearSession() {
  session.token = null; session.username = null; session.role = null;
  session.display = null; session.permissions = [];
  localStorage.removeItem(TOKEN_KEY);
}

function showLogin(message) {
  document.getElementById("login").hidden = false;
  document.getElementById("li-err").textContent = message || "";
  document.getElementById("li-pass").value = "";
  document.getElementById("li-user").focus();
}

function hideLogin() { document.getElementById("login").hidden = true; }

async function doLogin(evt) {
  evt.preventDefault();
  const username = document.getElementById("li-user").value.trim();
  const password = document.getElementById("li-pass").value;
  try {
    const s = await api("POST", "/login", { username, password });
    applySession(s);
    hideLogin();
    toast(`Signed in as ${s.username} (${s.role})`);
    switchView("catalog");
    checkHealth();
  } catch (e) {
    document.getElementById("li-err").textContent = e.message;
  }
}

async function doLogout() {
  try { await api("POST", "/logout", {}); } catch { /* ignore */ }
  clearSession();
  showLogin("Signed out.");
}

async function bootstrap() {
  document.getElementById("login-form").addEventListener("submit", doLogin);
  document.getElementById("btn-logout").addEventListener("click", doLogout);
  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => switchView(t.dataset.view)));

  // "Launch range" buttons on catalog cards.
  document.addEventListener("click", async (e) => {
    const sid = e.target?.dataset?.launch;
    if (!sid) return;
    try {
      const r = await api("POST", "/ranges", { scenario_id: sid });
      toast(`Range ${r.id} created for ${sid}`);
      switchView("ranges");
    } catch (err) { toast(err.message, "err"); }
  });

  const saved = localStorage.getItem(TOKEN_KEY);
  if (saved) {
    session.token = saved;
    try {
      const me = await api("GET", "/me");
      applySession(me);
      hideLogin();
      switchView("catalog");
      checkHealth();
      setInterval(checkHealth, 15000);
      return;
    } catch { clearSession(); }
  }
  showLogin();
}

bootstrap();
