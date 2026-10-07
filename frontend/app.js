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
    // Session expired or revoked - force re-login.
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
  const guide = can("range:create") ? `
    <div class="guide">
      <div class="steps">
        <span><span class="num">1</span><strong>Pick a scenario</strong> below</span><span class="arrow">→</span>
        <span><span class="num">2</span>Prepare the range</span><span class="arrow">→</span>
        <span><span class="num">3</span>Start the exercise</span><span class="arrow">→</span>
        <span><span class="num">4</span>Run techniques &amp; watch detections</span>
      </div>
    </div>` : `
    <div class="guide"><div class="steps">
      <span>Signed in as <strong>${esc(session.role)}</strong>. Browse what the lab can run here,
      then go to <strong>Exercise</strong> once an instructor starts one.</span>
    </div></div>`;

  m.innerHTML = guide + `
    <div class="toolbar">
      <input id="q" placeholder="Search scenarios…" style="min-width:220px" />
      <select id="f-diff"><option value="">Any difficulty</option>
        <option>introductory</option><option>intermediate</option><option>advanced</option></select>
      <select id="f-plat"><option value="">Any platform</option>
        <option>windows</option><option>linux</option><option>docker</option></select>
      <button class="ghost" id="btn-search">Filter</button>
      <span class="faint" id="scenario-count" style="margin-left:auto;font-size:12.5px"></span>
    </div>
    <div class="grid" id="scenarios"></div>

    <details class="panel" id="modules-panel" style="margin-top:var(--s6)">
      <summary style="cursor:pointer;font-weight:650;font-size:14px">
        TTP behaviour modules
        <span class="faint" style="font-weight:400">— the individual techniques scenarios are built from</span>
      </summary>
      <div style="margin-top:var(--s4)">
        <div class="toolbar">
          <select id="m-plat"><option value="">Any platform</option>
            <option>windows</option><option>linux</option><option>docker</option></select>
          <select id="m-safe"><option value="">Any safety class</option>
            <option>S0</option><option>S1</option><option>S2</option></select>
          <select id="m-exec"><option value="">Any execution</option>
            <option value="real">⚡ Real exec</option><option value="sim">◦ Simulated</option></select>
          <button class="ghost" id="btn-msearch">Filter modules</button>
        </div>
        <div class="grid" id="modules"></div>
      </div>
    </details>`;

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
    document.getElementById("scenario-count").textContent =
      `${scenarios.length} scenario${scenarios.length === 1 ? "" : "s"}`;
    if (!scenarios.length) {
      wrap.style.display = "block";
      wrap.innerHTML = emptyState("🔍", "No scenarios match",
        "Try a different difficulty or platform, or clear the search box.");
    } else {
      wrap.style.display = "";
    }
  }

  async function loadModules() {
    const p = new URLSearchParams();
    const plat = document.getElementById("m-plat").value;
    const safe = document.getElementById("m-safe").value;
    if (plat) p.set("platform", plat);
    if (safe) p.set("safety_class", safe);
    let mods = await api("GET", "/modules?" + p.toString());
    // Execution capability is a frontend-derived property (does the module ship
    // a spec?), so filter it client-side rather than adding an API parameter.
    const exec = document.getElementById("m-exec").value;
    if (exec === "real") mods = mods.filter(moduleIsRealCapable);
    else if (exec === "sim") mods = mods.filter((m) => !moduleIsRealCapable(m));
    const wrap = document.getElementById("modules");
    wrap.innerHTML = "";
    if (!mods.length) {
      wrap.style.display = "block";
      wrap.innerHTML = emptyState("🔍", "No modules match", "Clear a filter to see more.");
    } else {
      wrap.style.display = "";
      mods.forEach((mm) => wrap.appendChild(moduleCard(mm)));
    }
  }

  document.getElementById("btn-search").onclick = loadScenarios;
  document.getElementById("btn-msearch").onclick = loadModules;
  document.getElementById("q").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); loadScenarios(); }
  });
  // Modules are secondary: load them only when the section is first opened.
  const panel = document.getElementById("modules-panel");
  panel.addEventListener("toggle", () => {
    if (panel.open && !panel.dataset.loaded) { panel.dataset.loaded = "1"; loadModules(); }
  }, { once: false });
  await loadScenarios();
}

function scenarioCard(s) {
  const techs = (s.technique_ids || []).map((t) => `<span class="tag tech">${t}</span>`).join(" ");
  const dur = (s.duration_min || []).join("–");
  const cta = can("range:create")
    ? `<button class="act" data-launch="${esc(s.id)}">Launch range →</button>`
    : `<span class="faint" style="font-size:12px">Instructor-launched</span>`;
  return el(`<div class="card mode-${esc(s.mode)}">
    <div class="row" style="justify-content:space-between">
      <h4>${esc(s.name)}</h4><span class="tag mode">${esc(s.mode)}</span>
    </div>
    <p class="mono faint" style="font-size:11.5px">${esc(s.id)} · ${esc(s.difficulty)} · ${dur} min</p>
    <p>${esc(s.team_objective)}</p>
    <div class="row">${techs}</div>
    <div class="row" style="margin-top:14px;justify-content:space-between">
      ${cta}
      <span class="faint" style="font-size:11.5px">${(s.module_ids || []).length} modules</span>
    </div>
  </div>`);
}

function execBadge(m) {
  // Windows modules always simulate; Linux/Docker modules with a spec run for
  // real when Docker is up. The badge states the capability, not the live state,
  // so it is stable regardless of whether Docker happens to be connected.
  return moduleIsRealCapable(m)
    ? `<span class="exec-badge real" title="Executes a real command in an isolated container when Docker is connected">⚡ Real exec</span>`
    : `<span class="exec-badge sim" title="Emits declared telemetry; ${esc(m.platform)} behaviour needs the VM tier to run for real">◦ Simulated</span>`;
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
    <div class="row" style="margin:6px 0">${execBadge(m)}${techs}</div>
    <p>${esc(m.detection_notes || "")}</p>
    <p class="muted">Cleanup: ${esc(m.cleanup || "-")}</p>
  </div>`);
}

// ---------------- Ranges view ----------------
async function viewRanges() {
  const m = $main();
  const canManage = can("range:lifecycle");
  const creator = can("range:create") ? `
    <div class="toolbar">
      <select id="new-scenario" style="min-width:220px"></select>
      <button class="act" id="btn-create">+ Create range</button>
      <button class="ghost" id="btn-refresh">↻ Refresh</button>
    </div>` : `<div class="toolbar"><button class="ghost" id="btn-refresh">↻ Refresh</button></div>`;

  m.innerHTML = `${creator}
    <div class="table-wrap">
      <table><thead><tr>
        <th>Range</th><th>Lifecycle</th><th style="width:40%">Next step</th>
      </tr></thead><tbody id="range-rows"></tbody></table>
    </div>`;

  if (can("range:create")) {
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
  }
  // Wrapped, not passed bare: a click handler receives the event as its first
  // argument, and loadRanges must never take a permission from a caller.
  document.getElementById("btn-refresh").onclick = () => loadRanges();
  await loadRanges();
}

// Milestones shown in the lifecycle stepper, mapped from raw states.
const MILESTONES = ["Requested", "Prepared", "Running", "Complete"];
function milestoneIndex(state) {
  if (["REQUESTED", "PREFLIGHT", "PROVISIONING", "SEEDING"].includes(state)) return 0;
  if (state === "READY") return 1;
  if (["RUNNING", "PAUSED"].includes(state)) return 2;
  if (["COMPLETING", "EVIDENCE_LOCKED", "ARCHIVED", "DESTROYED"].includes(state)) return 3;
  return -1; // QUARANTINED
}
function stepperHtml(state) {
  if (state === "QUARANTINED") return `<span class="badge QUARANTINED">QUARANTINED</span>`;
  const cur = milestoneIndex(state);
  return `<div class="stepper">` + MILESTONES.map((label, i) => {
    const cls = i < cur ? "done" : (i === cur ? "current" : "");
    const line = i > 0 ? `<span class="step-line ${i <= cur ? "done" : ""}"></span>` : "";
    return `${line}<span class="step ${cls}"><span class="dot"></span><span class="lbl">${label}</span></span>`;
  }).join("") + `</div>`;
}

async function loadRanges() {
  // Always derived here. This used to be a defaulted parameter, and binding the
  // function straight to a click handler passed the PointerEvent in as that
  // parameter - truthy - so one press of Refresh showed every lifecycle control
  // to roles that hold none of those permissions.
  const canManage = can("range:lifecycle");
  const ranges = await api("GET", "/ranges");
  const tb = document.getElementById("range-rows");
  tb.innerHTML = "";
  ranges.forEach((r) => {
    const targets = (r.meta && r.meta.targets) ? r.meta.targets : null;
    const targetHtml = targets
      ? `<div class="faint" style="font-size:11px;margin-top:4px">🎯 targets: ${targets.map(t => `<span class="mono">${esc(t.hostname)}</span>`).join(", ")}</div>`
      : "";
    const row = el(`<tr>
      <td><div><strong class="mono" style="font-size:12px">${esc(r.id)}</strong></div>
        <div class="faint" style="font-size:11.5px">${esc(r.scenario_id)}</div></td>
      <td>${stepperHtml(r.state)}<div class="faint mono" style="font-size:10.5px;margin-top:5px">${esc(r.state)}</div>${targetHtml}</td>
      <td class="row"></td></tr>`);
    const actions = row.querySelector("td.row");
    const idx = milestoneIndex(r.state);

    if (!canManage) {
      actions.innerHTML = `<span class="faint" style="font-size:12px">read-only</span>`;
    } else if (r.state === "QUARANTINED") {
      const d = el(`<button class="ghost danger">Destroy</button>`);
      d.onclick = () => advance(r.id, "destroy");
      actions.appendChild(d);
    } else if (idx === 0) {
      const prep = el(`<button class="act">⚡ Prepare range</button>`);
      prep.onclick = () => prepareRange(r.id);
      actions.appendChild(prep);
      actions.appendChild(hint("Provisions the VMs and networks, then seeds identities (≈ 4 steps, one click)."));
    } else if (r.state === "READY") {
      const b = el(`<button class="act">▶ Start exercise</button>`);
      b.onclick = () => startExercise(r.id);
      actions.appendChild(b);
    } else if (["RUNNING", "PAUSED"].includes(r.state)) {
      const b = el(`<button class="ghost">Open exercise →</button>`);
      b.onclick = () => { switchView("exercise"); };
      actions.appendChild(b);
    } else {
      actions.innerHTML = `<span class="faint" style="font-size:12px">${esc(r.state.toLowerCase())}</span>`;
    }
    if (canManage && ["READY", "RUNNING", "PAUSED"].includes(r.state)) {
      const rs = el(`<button class="ghost" title="Recycle the range targets to a clean state">↻ Reset</button>`);
      rs.onclick = () => advance(r.id, "reset");
      actions.appendChild(rs);
    }
    if (canManage && !["DESTROYED", "ARCHIVED", "QUARANTINED"].includes(r.state) && idx >= 0) {
      const q = el(`<button class="ghost danger" title="Isolate this range">⚠</button>`);
      q.onclick = () => advance(r.id, "quarantine");
      actions.appendChild(q);
    }
    tb.appendChild(row);
  });
  if (!ranges.length) {
    tb.innerHTML = `<tr><td colspan="3"><div class="empty">
      <span class="ico">🖥️</span><h4>No ranges yet</h4>
      <p>${can("range:create")
        ? "Pick a scenario above and hit <strong>Create range</strong> to spin up an isolated environment."
        : "An instructor hasn't created any ranges yet."}</p></div></td></tr>`;
  }
}

function hint(text) {
  return el(`<span class="faint" style="font-size:11px;flex-basis:100%;margin-top:2px">${esc(text)}</span>`);
}

async function prepareRange(rid) {
  const steps = ["preflight", "provision", "seed", "ready"];
  try {
    toast("Preparing range…");
    for (const s of steps) await api("POST", `/ranges/${rid}/actions`, { action: s });
    toast("Range ready - you can start the exercise", "ok");
    await loadRanges();
  } catch (e) { toast(e.message, "err"); await loadRanges(); }
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
    m.innerHTML = `<div class="empty"><span class="ico">🎯</span>
      <h4>No exercises running</h4>
      <p>${can("range:create")
        ? "Head to <strong>Ranges</strong>, prepare a range, and press <strong>Start exercise</strong>."
        : "Once an instructor starts an exercise, it appears here for you to join."}</p></div>`;
    return;
  }
  if (!state.exercise || !exercises.some((e) => e.id === state.exercise)) {
    state.exercise = exercises[0].id;
  }

  const isBlue = session.role === "blue";

  // Role-aware action panels.
  const panels = [];
  panels.push(missionBrief());
  if (can("module:execute")) panels.push(`
    <div class="panel">
      <div class="phead">① Attack console <span class="tag tech">red</span></div>
      <div class="phelp">Pick a technique and launch it. <strong>⚡ Real</strong> modules execute a real command in an isolated container; <strong>◦ sim</strong> modules (all Windows behaviour) emit declared telemetry. The output becomes the logs blue has to find.</div>
      <div id="exec-mode-note"></div>
      <div class="row"><select id="mod-select" style="flex:1"></select>
        <button class="act" id="btn-run-mod">▶ Launch attack</button></div>
      <div id="attack-result" style="margin-top:10px"></div>
    </div>`);
  if (can("exercise:inject")) panels.push(`
    <div class="panel">
      <div class="phead">Instructor inject</div>
      <div class="phelp">Publish an event (user report, escalation, hint) onto the shared timeline.</div>
      <div class="row"><input id="inject-text" placeholder="e.g. User reports a suspicious email" style="flex:1" />
        <button class="ghost" id="btn-inject">Inject</button></div>
    </div>`);
  // Red and blue both record evidence, but they are recording opposite things:
  // blue proves what it caught, red documents what it did. The report compares
  // the two, which is where ATT&CK coverage comes from - so the panel has to
  // speak in the language of whoever is looking at it.
  if (can("exercise:submit_evidence")) {
    const ev = isBlue ? {
      head: "③ Raise a finding",
      help: "When a log line proves malicious activity, hit <strong>Use as evidence</strong> on it in the search results, or type your finding here. Each item is hashed for integrity.",
      hint: "e.g. Binary written to /tmp and executed as root on host:victim",
    } : session.role === "red" ? {
      head: "Log your attack path",
      help: "Record what you did and what it got you. This is not defender work: the after-action report compares your declared path against what blue actually detected, and that gap is the coverage finding. Each item is hashed for integrity.",
      hint: "e.g. Wrote /tmp/payload.sh and executed it as root on victim",
    } : {
      head: "Record evidence",
      help: "You run both sides, so log the attack steps you take and the findings you make. Each item is hashed for integrity.",
      hint: "e.g. Executed payload as root, then alerted on the nested shell",
    };
    panels.push(`
    <div class="panel">
      <div class="phead">${ev.head} <span class="tag role">${esc(session.role)}</span></div>
      <div class="phelp">${ev.help}</div>
      <div class="row"><input id="ev-text" placeholder="${esc(ev.hint)}" style="flex:1" />
        <button class="ghost" id="btn-ev">Submit</button></div>
    </div>`);
  }
  panels.push(`
    <div class="panel">
      <div class="phead">${isBlue ? "④ Attribute the technique" : "Detection"}</div>
      <div class="phelp">${isBlue
        ? "Alerts fire <strong>automatically</strong> from detection rules. Once you have worked out which ATT&amp;CK technique the activity maps to, record your verdict here."
        : "Rules fire <strong>automatically</strong> when a module runs. Add a manual verdict only if needed."}</div>
      <div class="row">
        <input id="det-tech" placeholder="T1059" style="width:88px" />
        <select id="det-verdict"><option>detected</option><option>missed</option><option>false_positive</option></select>
        <button class="ghost" id="btn-det">Record</button>
      </div>
    </div>`);
  if (can("scoring:read")) panels.push(`
    <div class="panel">
      <div class="phead">Score</div>
      <div class="phelp">Detection &amp; red-execution are computed from the timeline. Set the rubric dimensions and compute.</div>
      <div id="score-panel"></div>
    </div>`);

  const canEnd = can("range:lifecycle");
  m.innerHTML = `
    <div class="toolbar">
      <select id="ex-select" style="min-width:230px"></select>
      <button class="ghost" id="btn-report">📄 Report</button>
      ${canEnd ? '<button class="ghost" id="btn-end">■ End exercise</button>' : ""}
    </div>
    <div class="split">
      <div>
        <div class="panel" id="ex-meta"></div>
        ${panels.join("")}
      </div>
      <div>
        ${isBlue ? socConsole() : `
        <div class="row" style="justify-content:space-between;align-items:baseline">
          <h3 style="margin:0">Live timeline <span class="faint">(UTC)</span></h3>
          <button class="ghost" id="btn-tl-refresh" style="padding:5px 10px">↻</button>
        </div>
        <div class="legend">
          <span><span class="tag s0">real</span> genuine container output</span>
          <span><span class="tag" style="opacity:.6">sim</span> simulated telemetry</span>
          <span><span style="color:var(--amber)">◈</span> detection fired</span>
        </div>
        <ul class="timeline" id="timeline"></ul>`}
      </div>
    </div>`;

  const sel = document.getElementById("ex-select");
  exercises.forEach((e) =>
    sel.appendChild(el(`<option value="${esc(e.id)}" ${e.id === state.exercise ? "selected" : ""}>${esc(e.id)} · ${esc(e.status)}</option>`)));
  sel.onchange = () => { state.exercise = sel.value; viewExercise(); };

  const scenario = await loadExerciseMeta();
  if (can("module:execute")) await loadModuleSelect(scenario);
  if (can("scoring:read")) await buildScorePanel();
  if (isBlue) { await initSocConsole(); } else { await loadTimeline(); }

  bind("btn-run-mod", runModule);
  bind("btn-inject", doInject);
  bind("btn-ev", doEvidence);
  bind("btn-det", doDetection);
  bind("btn-report", showReport);
  bind("btn-end", endExercise);
  bind("btn-tl-refresh", loadTimeline);
}

// ---------------- Mission brief (what am I supposed to do?) --------------
const BRIEFS = {
  red: {
    title: "You are RED (attacker)",
    goal: "Compromise the target and complete the scenario's techniques.",
    steps: ["Pick a technique in the <strong>Attack console</strong> and launch it.",
            "Read the result: it shows what actually ran on the target host.",
            "Chain the next technique. Your actions generate the real logs blue must find."],
  },
  blue: {
    title: "You are BLUE (defender)",
    goal: "Detect what the attacker did, prove it with evidence, and attribute the technique.",
    steps: ["Open <strong>Alerts</strong> in the SOC console. That is your lead, not your answer.",
            "Switch to <strong>All activity</strong> and hunt the raw logs around it (try <span class='mono'>root</span>, <span class='mono'>/tmp</span>, <span class='mono'>shell</span>).",
            "Hit <strong>Use as evidence</strong> on a damning line, then attribute the ATT&amp;CK technique."],
  },
  purple: {
    title: "You are PURPLE (detection engineering)",
    goal: "Replay attacker behaviour and improve detection coverage.",
    steps: ["Launch a technique from the attack console.",
            "Check which rules fired and which did not (coverage gaps).",
            "Tune, replay, and compare before/after in the report."],
  },
  instructor: {
    title: "You are the INSTRUCTOR",
    goal: "Run the exercise, inject events, and grade the outcome.",
    steps: ["Launch techniques yourself, or let red drive.",
            "Use <strong>Inject</strong> to push a user report or escalation.",
            "End the exercise, then open the <strong>Report</strong> to score and export."],
  },
};

function missionBrief() {
  const b = BRIEFS[session.role] || BRIEFS.instructor;
  return `<div class="panel" style="border-color:rgba(76,159,255,.35)">
    <div class="phead">${esc(b.title)}</div>
    <div class="phelp"><strong>Goal:</strong> ${b.goal}</div>
    <ol style="margin:8px 0 0;padding-left:20px;font-size:12.5px;color:var(--muted);line-height:1.7">
      ${b.steps.map((s) => `<li>${s}</li>`).join("")}
    </ol></div>`;
}

// ---------------- Blue SOC console (log search) --------------------------
/* Each hunt says what it finds, so the buttons teach the investigation rather
   than just pasting a string into the box. */
const HUNTS = [
  ["root", "Processes running as uid 0"],
  ["/tmp", "Files dropped in a world-writable directory"],
  ["shell", "A shell spawned inside a service"],
  ["payload", "Suspicious file names"],
  ["secret", "Credential and secret access"],
  ["curl", "Download or exfiltration attempts"],
];

function socConsole() {
  return `
    <div class="row" style="justify-content:space-between;align-items:baseline">
      <h3 style="margin:0">② SOC console <span class="faint">log search</span></h3>
      <button class="ghost" id="btn-log-search" style="padding:5px 10px">↻ Refresh</button>
    </div>
    <div class="phelp" style="margin:2px 0 12px">
      This is the telemetry the environment produced. The attacker's own tooling
      is hidden, so work it out from the evidence, like a real SOC.
    </div>

    <div class="scope-bar" id="log-scope">
      <button class="chip" data-scope="detection">
        <span class="chip-dot warn"></span>Alerts<span class="chip-n" id="n-alerts">–</span>
      </button>
      <button class="chip active" data-scope="">
        <span class="chip-dot"></span>All activity<span class="chip-n" id="n-all">–</span>
      </button>
      <span class="faint" style="font-size:11.5px;margin-left:auto">Start with alerts, then widen</span>
    </div>

    <div class="search-row">
      <span class="search-ico" aria-hidden="true">⌕</span>
      <input id="log-q" placeholder="Search log text, host or event type…" autocomplete="off" />
      <button class="search-clear" id="log-clear" hidden aria-label="Clear search">×</button>
    </div>

    <div class="toolbar" style="margin:8px 0 10px">
      <select id="log-kind" style="max-width:170px"><option value="">Any event type</option></select>
      <select id="log-source" style="max-width:170px"><option value="">Any source</option></select>
      <button class="ghost" id="log-reset" hidden style="padding:5px 10px">Reset filters</button>
    </div>

    <div class="hunts">
      <span class="faint" style="font-size:11.5px">Hunt for:</span>
      ${HUNTS.map(([h, why]) =>
        `<button class="hunt" data-hunt="${esc(h)}" title="${esc(why)}">${esc(h)}</button>`).join("")}
    </div>

    <div class="siem">
      <div class="siem-bar">
        <div id="log-count" class="log-count"></div>
        <div class="histo" id="log-histo" title="Events over the exercise timeline"></div>
      </div>
      <div class="pivots" id="log-pivots"></div>
      <div class="loghead">
        <span>Time</span><span>Source</span><span>Event</span><span>Message</span>
      </div>
      <ul class="logtable" id="log-results"></ul>
    </div>`;
}

async function initSocConsole() {
  const q = document.getElementById("log-q");
  const kindSel = document.getElementById("log-kind");
  const srcSel = document.getElementById("log-source");

  try {
    const meta = await api("GET", `/exercises/${state.exercise}/log-sources`);
    (meta.kinds || []).forEach((k) => kindSel.appendChild(el(`<option value="${esc(k)}">${esc(k)}</option>`)));
    (meta.sources || []).forEach((s) => srcSel.appendChild(el(`<option value="${esc(s)}">${esc(s)}</option>`)));
  } catch (e) { /* meta is best-effort */ }

  kindSel.onchange = () => { syncScopeChips(); runLogSearch(); };
  srcSel.onchange = runLogSearch;

  let t;
  q.oninput = () => { clearTimeout(t); t = setTimeout(runLogSearch, 250); };
  q.onkeydown = (e) => {
    if (e.key === "Enter") { e.preventDefault(); clearTimeout(t); runLogSearch(); }
    if (e.key === "Escape") { q.value = ""; runLogSearch(); }
  };

  document.getElementById("log-clear").onclick = () => { q.value = ""; q.focus(); runLogSearch(); };
  document.getElementById("log-reset").onclick = () => {
    q.value = ""; kindSel.value = ""; srcSel.value = "";
    syncScopeChips(); runLogSearch();
  };

  // The alert / all-activity chips are the primary path; they drive the same
  // kind filter the dropdown does, so there is one source of truth.
  document.querySelectorAll("#log-scope .chip").forEach((c) => {
    c.onclick = () => { kindSel.value = c.dataset.scope; syncScopeChips(); runLogSearch(); };
  });

  document.querySelectorAll(".hunt").forEach((b) => {
    b.onclick = () => { q.value = b.dataset.hunt; runLogSearch(); };
  });
  bind("btn-log-search", async () => { await refreshScopeCounts(); await runLogSearch(); });

  await refreshScopeCounts();
  await runLogSearch();
}

function syncScopeChips() {
  const kind = document.getElementById("log-kind")?.value || "";
  document.querySelectorAll("#log-scope .chip").forEach((c) =>
    c.classList.toggle("active", c.dataset.scope === kind));
}

/* Blue should be able to see at a glance whether anything has fired yet. */
async function refreshScopeCounts() {
  try {
    const [alerts, all] = await Promise.all([
      api("GET", `/exercises/${state.exercise}/logs?kind=detection`),
      api("GET", `/exercises/${state.exercise}/logs`),
    ]);
    const a = document.getElementById("n-alerts");
    const t = document.getElementById("n-all");
    if (a) { a.textContent = alerts.count; a.classList.toggle("hot", alerts.count > 0); }
    if (t) t.textContent = all.count;
  } catch { /* counts are best-effort */ }
}

async function runLogSearch() {
  const p = new URLSearchParams();
  const q = document.getElementById("log-q")?.value.trim();
  const kind = document.getElementById("log-kind")?.value;
  const source = document.getElementById("log-source")?.value;
  if (q) p.set("q", q);
  if (kind) p.set("kind", kind);
  if (source) p.set("source", source);

  const filtered = Boolean(q || kind || source);
  const clearBtn = document.getElementById("log-clear");
  const resetBtn = document.getElementById("log-reset");
  if (clearBtn) clearBtn.hidden = !q;
  if (resetBtn) resetBtn.hidden = !filtered;
  syncScopeChips();

  try {
    const res = await api("GET", `/exercises/${state.exercise}/logs?` + p.toString());
    const ul = document.getElementById("log-results");
    const countEl = document.getElementById("log-count");

    const bits = [];
    if (q) bits.push(`matching <strong>${esc(q)}</strong>`);
    if (kind) bits.push(`of type <strong>${esc(kind)}</strong>`);
    if (source) bits.push(`from <strong>${esc(source)}</strong>`);
    countEl.innerHTML = `<strong>${res.count}</strong> event${res.count === 1 ? "" : "s"}`
      + (bits.length ? ` ${bits.join(", ")}` : "");

    renderHisto(res.results);
    renderPivots(res.results);

    ul.innerHTML = "";
    if (!res.results.length) {
      // Distinguish "your filter is too narrow" from "nothing has happened yet":
      // they need opposite actions from the analyst.
      ul.innerHTML = filtered
        ? `<li class="logempty">${emptyState("⌕", "No events match",
            "Nothing in this exercise matches that filter. Widen it with Reset filters, or try one of the hunts above.")}</li>`
        : `<li class="logempty">${emptyState("◷", "Nothing has happened yet",
            "The attacker has not acted in this exercise. Press Refresh once they do.")}</li>`;
      return;
    }
    res.results.forEach((ev) => ul.appendChild(logRow(ev, q)));
  } catch (e) { toast(e.message, "err"); }
}

/* Events bucketed over the window the results span - the "when did this spike"
   read every SIEM puts above its result list. */
function renderHisto(results) {
  const host = document.getElementById("log-histo");
  if (!host) return;
  if (results.length < 2) { host.innerHTML = ""; return; }
  const ts = results.map((e) => Date.parse(e.ts_utc)).filter(Number.isFinite);
  const min = Math.min(...ts), max = Math.max(...ts);
  const BUCKETS = 28;
  const span = Math.max(max - min, 1);
  const counts = new Array(BUCKETS).fill(0);
  ts.forEach((t) => {
    const i = Math.min(BUCKETS - 1, Math.floor(((t - min) / span) * BUCKETS));
    counts[i] += 1;
  });
  const peak = Math.max(...counts, 1);
  host.innerHTML = counts.map((c) =>
    `<span class="hbar" style="height:${Math.max(2, Math.round((c / peak) * 100))}%"
       title="${c} event${c === 1 ? "" : "s"}"></span>`).join("");
}

/* Clickable field summary: the pivot that turns a list of lines into an
   investigation ("which host is noisiest, what kind of event is this"). */
function renderPivots(results) {
  const host = document.getElementById("log-pivots");
  if (!host) return;
  const tally = (key) => {
    const m = new Map();
    results.forEach((e) => { const v = e[key]; if (v) m.set(v, (m.get(v) || 0) + 1); });
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  };
  const group = (label, key, rows) => rows.length
    ? `<div class="pivot"><span class="pivot-h">${label}</span>${rows.map(([v, n]) =>
        `<button class="pivot-v" data-field="${key}" data-value="${esc(v)}">
           ${esc(v)}<span class="pivot-n">${n}</span></button>`).join("")}</div>`
    : "";
  host.innerHTML = group("Sources", "source", tally("source"))
                 + group("Event types", "kind", tally("kind"));
  host.querySelectorAll(".pivot-v").forEach((b) => {
    b.onclick = () => {
      const sel = document.getElementById(b.dataset.field === "source" ? "log-source" : "log-kind");
      if (sel) { sel.value = b.dataset.value; runLogSearch(); }
    };
  });
}

/* Highlight the matched term so the analyst can see WHY a line came back,
   rather than re-reading it to find the hit. Escaped first, so the mark is the
   only markup introduced. */
function highlight(text, needle) {
  const safe = esc(text);
  if (!needle) return safe;
  const pattern = esc(needle).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  try {
    return safe.replace(new RegExp(pattern, "gi"), (hit) => `<mark>${hit}</mark>`);
  } catch { return safe; }
}

function logRow(ev, needle) {
  const p = ev.payload || {};
  const isAlert = ev.kind === "detection";
  const text = p.line || p.stderr || p.title || p.text || ev.kind;
  const sev = (p.severity || "").toLowerCase();
  const msg = isAlert
    ? `<strong class="alert-k">ALERT</strong> ${esc(p.title || "")}
       <span class="tag sev-${esc(sev)}">${esc(sev.toUpperCase())}</span>
       ${p.latency_s !== undefined ? `<span class="faint">MTTD ${esc(p.latency_s)}s</span>` : ""}`
    : `<span class="msg">${highlight(String(text), needle)}</span>`;

  const li = el(`<li class="logrow ${isAlert ? "det" : "out"}">
    <div class="lr">
      <span class="lr-t">${esc(ev.ts_utc.slice(11, 23))}</span>
      <span class="lr-s" title="${esc(ev.source || "")}">${esc(ev.source || "-")}</span>
      <span class="lr-k">${esc(ev.kind)}</span>
      <span class="lr-m">${msg}</span>
    </div>
    <div class="lr-actions">
      <button class="ghost use-ev">Use as evidence</button>
      <button class="ghost lr-expand">Raw event</button>
    </div>
    <pre class="lr-raw" hidden>${esc(JSON.stringify(ev, null, 2))}</pre>
  </li>`);

  const raw = li.querySelector(".lr-raw");
  const exp = li.querySelector(".lr-expand");
  exp.onclick = () => {
    raw.hidden = !raw.hidden;
    exp.textContent = raw.hidden ? "Raw event" : "Hide raw";
  };
  li.querySelector(".use-ev").onclick = async () => {
    const box = document.getElementById("ev-text");
    const desc = `${ev.source}: ${String(text).slice(0, 160)}`;
    if (box) { box.value = desc; box.focus(); }
    toast("Copied to the finding box. Review, then Submit.");
  };
  return li;
}

function bind(id, fn) {
  const el2 = document.getElementById(id);
  if (el2) el2.onclick = fn;
}

async function loadExerciseMeta() {
  const ex = await api("GET", `/exercises/${state.exercise}`);
  state.range = ex.range_id;
  const scenario = await api("GET", `/scenarios/${ex.scenario_id}`);
  const statusCls = ex.status === "running" ? "RUNNING" : "";
  document.getElementById("ex-meta").innerHTML = `
    <div class="row" style="justify-content:space-between;align-items:flex-start">
      <div><div class="phead" style="font-size:15px">${esc(scenario.name)}</div>
        <div class="faint mono" style="font-size:11px">${esc(ex.id)}</div></div>
      <span class="badge ${statusCls}">${esc(ex.status)}</span>
    </div>
    <p style="margin:10px 0 12px">${esc(scenario.team_objective)}</p>
    <div class="kv">
      <dt>Techniques</dt><dd class="row" style="gap:5px">${(scenario.technique_ids || []).map(t => `<span class="tag tech">${esc(t)}</span>`).join("")}</dd>
      <dt>Objectives</dt><dd>${(scenario.objectives || []).map(o => `<span class="tag mode">${esc(o.role)} · ${o.points}pt</span>`).join(" ")}</dd>
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
    // Options are plain text, so the real/sim call is carried in a prefix glyph
    // rather than a styled badge.
    const run = moduleIsRealCapable(mm) ? "⚡ real" : "◦ sim";
    sel.appendChild(el(`<option value="${esc(mm.id)}">${star}${run} · ${esc(mm.name)} [${esc(mm.safety_class)}/${esc(mm.platform)}]</option>`));
  });

  // One live line that reflects whether Docker is actually connected, since a
  // real-capable module still simulates when it is not.
  const note = document.getElementById("exec-mode-note");
  if (note) {
    note.innerHTML = execState.real
      ? `<div class="mode-note ok">⚡ Docker connected — <strong>real</strong> modules execute for real. Windows modules still simulate.</div>`
      : `<div class="mode-note warn">◦ Docker not connected — <strong>every</strong> module will simulate, including the real-capable ones. Start Docker and restart the server for real execution.</div>`;
  }
}

async function runModule() {
  try {
    const mid = document.getElementById("mod-select").value;
    const res = await api("POST", `/exercises/${state.exercise}/modules`, { module_id: mid });
    const how = res.real ? `ran for real via ${res.adapter}` : "simulated";
    const det = res.detections_fired ? `, ${res.detections_fired} detection(s) fired` : "";
    toast(`${res.executed} ${how} → ${res.events_recorded} events${det}`);
    const out = document.getElementById("attack-result");
    if (out) {
      const s = res.summary || {};
      out.innerHTML = `<div class="detline" style="border-left-color:var(--green)">
        <div><strong>${res.real ? "✓ Executed for real" : "✓ Simulated"}</strong>
          ${res.real ? `<span class="tag s0">real</span>` : `<span class="tag">sim</span>`}
          <span class="tag tech">${(res.techniques || []).join(", ")}</span></div>
        <div class="faint" style="font-size:11.5px;margin-top:3px">
          ${res.real ? `Ran on ${esc(s.image || "target")} (exit ${esc(String(s.exit_code))}, ${esc(String(s.duration_s))}s). ` : ""}
          Generated <strong>${res.events_recorded}</strong> log event(s);
          <strong>${res.detections_fired || 0}</strong> detection(s) fired.
          ${res.detections_fired ? "Blue can now see the alert." : "Blue must find this in the raw logs."}
        </div></div>`;
    }
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

const DERIVED_DIMS = ["red_execution", "detection"];
const MANUAL_DIMS = ["investigation", "response", "collaboration"];

async function buildScorePanel() {
  const p = document.getElementById("score-panel");
  let derived = { detection: 0, red_execution: 0, _detail: {} };
  try { derived = await api("GET", `/exercises/${state.exercise}/derived-scores`); } catch { /* none yet */ }
  const d = derived._detail || {};
  const mttd = d.mean_mttd_s == null ? "-" : `${d.mean_mttd_s}s`;

  const derivedRows = DERIVED_DIMS.map((dim) =>
    `<div class="row" style="justify-content:space-between;margin-bottom:6px">
      <label style="color:var(--muted)">${dim} <span class="tag" style="font-size:10px">auto</span></label>
      <span class="mono" id="scv-${dim}" style="color:var(--green)">${derived[dim] ?? 0}</span></div>`
  ).join("");

  const manualRows = MANUAL_DIMS.map((dim) =>
    `<div class="row" style="justify-content:space-between;margin-bottom:6px">
      <label style="color:var(--muted)">${dim}</label>
      <input type="range" min="0" max="100" value="70" id="sc-${dim}" style="flex:1;margin:0 10px" />
      <span class="mono" id="scv-${dim}">70</span></div>`
  ).join("");

  p.innerHTML = derivedRows +
    `<p class="muted" style="font-size:11px;margin:2px 0 8px">Detection &amp; red-execution are
      derived from the timeline - coverage ${((d.coverage ?? 0) * 100).toFixed(0)}% ·
      log-fidelity ${((d.log_fidelity ?? 0) * 100).toFixed(0)}% · mean MTTD ${mttd}.</p>` +
    manualRows +
    `<button class="act" id="btn-score" style="margin-top:8px">Compute score</button>
     <div id="score-out" style="margin-top:12px"></div>`;
  MANUAL_DIMS.forEach((dim) => {
    const r = document.getElementById(`sc-${dim}`);
    r.oninput = () => { document.getElementById(`scv-${dim}`).textContent = r.value; };
  });
  document.getElementById("btn-score").onclick = computeScore;
}

async function computeScore() {
  try {
    const raw = {};
    MANUAL_DIMS.forEach((dim) => { raw[dim] = Number(document.getElementById(`sc-${dim}`).value); });
    const res = await api("POST", `/exercises/${state.exercise}/score`, { raw_scores: raw });
    const derivedSet = new Set((res.derived || {}).dimensions || []);
    const bars = res.dimensions.map((dd) => {
      const auto = derivedSet.has(dd.dimension) ? '<span class="tag" style="font-size:10px">auto</span>' : "";
      return `<div style="margin:6px 0"><div class="row" style="justify-content:space-between">
        <span class="muted">${dd.dimension} (×${dd.weight}) ${auto}</span><span class="mono">${dd.contribution}</span></div>
       <div class="bar"><span style="width:${dd.raw}%"></span></div></div>`;
    }).join("");
    document.getElementById("score-out").innerHTML =
      `<div class="row" style="justify-content:space-between"><h4>Total: ${res.total}</h4>
       <span class="muted">weighted ${res.weighted_before_penalty}</span></div>${bars}`;
    toast(`Score ${res.total}`);
  } catch (e) { toast(e.message, "err"); }
}

async function loadTimeline() {
  // Blue works from the SOC console instead of the raw timeline; refresh that.
  if (!document.getElementById("timeline")) {
    if (document.getElementById("log-results")) await runLogSearch();
    return;
  }
  const events = await api("GET", `/exercises/${state.exercise}/timeline`);
  const ul = document.getElementById("timeline");
  ul.innerHTML = "";
  events.slice().reverse().forEach((ev) => {
    const p = ev.payload || {};
    const tech = ev.technique_id ? `<span class="tag tech">${esc(ev.technique_id)}</span>` : "";
    const realTag = p.real === true ? '<span class="tag s0">real</span>'
      : (p.real === false ? '<span class="tag" style="opacity:.6">sim</span>' : "");
    let extra = "";
    let kindHtml = `<span class="kind">${esc(ev.kind)}</span>`;
    if (ev.kind === "process-output" && p.line) {
      extra = `<div class="logline">${esc(p.line)}</div>`;
    } else if (ev.kind === "process-stderr" && p.stderr) {
      extra = `<div class="logline" style="color:var(--amber)">${esc(p.stderr)}</div>`;
    } else if (ev.kind === "ttp-exec" && p.image) {
      extra = `<div class="mono muted" style="font-size:11px">${esc(p.image)} · exit ${esc(p.exit_code)} · ${esc(p.duration_s)}s</div>`;
    } else if (ev.kind === "detection") {
      kindHtml = `<span class="kind" style="color:var(--amber)">◈ detection</span>`;
      const sev = (p.severity || "").toUpperCase();
      extra = `<div class="detline"><strong>${esc(p.rule_id)}</strong> · ${esc(p.title)}
        <span class="tag ${p.basis === "log" ? "s0" : ""}">${esc(p.basis)}</span>
        <span class="muted">${esc(sev)} · MTTD ${esc(p.latency_s)}s</span></div>`;
    }
    const liClass = ev.kind === "detection" ? "det"
      : (ev.kind === "process-output" ? "out" : "");
    ul.appendChild(el(`<li class="${liClass}">
      <div class="ts">${esc(ev.ts_utc.slice(11, 23))} · ${esc(ev.source)}</div>
      <div>${kindHtml} ${tech} ${realTag}
        <span class="faint">- ${esc(ev.actor || "")}</span></div>
      ${extra}
    </li>`));
  });
  if (!events.length) ul.innerHTML = `<li class="faint" style="padding-left:0">No activity yet - run a module to populate the timeline.</li>`;
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
    const exid = state.exercise;
    m.innerHTML = `<div class="toolbar"><button class="ghost" id="back">← Back</button>
      <h2 style="margin:0;flex:1">After-action report</h2>
      <span class="faint" style="font-size:12px">Export:</span>
      <button class="ghost" data-dl="report.docx">DOCX</button>
      <button class="ghost" data-dl="report.html">PDF/HTML</button>
      <button class="ghost" data-dl="report.csv">CSV</button>
      <button class="ghost" data-dl="report.json">JSON</button></div>
      <div class="card"><h4>${esc(rep.scenario.name)} · ${esc(rep.scenario.mode)}</h4>
        <p class="mono muted">${esc(rep.exercise_id)} · ${esc(rep.status)}</p>
        <div class="kv">
          <dt>Expected techniques</dt><dd>${(cov.expected || []).join(", ") || "-"}</dd>
          <dt>Observed</dt><dd>${(cov.observed || []).join(", ") || "-"}</dd>
          <dt>Detected</dt><dd>${(cov.detected || []).join(", ") || "-"}</dd>
          <dt>Coverage gaps</dt><dd style="color:var(--red)">${(cov.gaps || []).join(", ") || "none"}</dd>
          <dt>Timeline events</dt><dd>${rep.timeline_events}</dd>
          <dt>Evidence items</dt><dd>${rep.evidence_count}</dd>
          <dt>Score</dt><dd>${rep.score ? rep.score.total : "not scored"}</dd>
        </div></div>
      <h3>Framework alignment <span class="faint" style="font-size:11px;text-transform:none">(curated crosswalk from ATT&amp;CK)</span></h3>
      <div class="card">${fwBlock(rep.framework_coverage || {})}</div>
      <h3>Recommendations</h3>
      <div class="card"><ul>${(rep.recommendations || []).map(r => `<li>${esc(r)}</li>`).join("")}</ul></div>
      <h3>Raw report JSON</h3><pre>${esc(JSON.stringify(rep, null, 2))}</pre>`;
    document.getElementById("back").onclick = () => switchView("exercise");
    m.querySelectorAll("[data-dl]").forEach((b) => {
      b.onclick = () => downloadFile(`/exercises/${exid}/${b.dataset.dl}`,
                                     `cyberrange-${b.dataset.dl}`);
    });
  } catch (e) { toast(e.message, "err"); }
}

function fwBlock(fw) {
  const row = (label, items) =>
    `<div style="margin:8px 0"><div class="muted" style="font-size:12px;margin-bottom:4px">${label}</div>
      <div class="row">${(items || []).map(x => `<span class="tag">${esc(x)}</span>`).join("") || '<span class="faint">none</span>'}</div></div>`;
  return row("NIST CSF 2.0 functions", fw.nist_csf) +
         row("NICE work roles", fw.nice) +
         row("CIS Controls v8", fw.cis) +
         row("NSA CAE Knowledge Units", fw.cae);
}

async function downloadFile(path, filename) {
  try {
    const res = await fetch("/api" + path,
      { headers: session.token ? { Authorization: "Bearer " + session.token } : {} });
    if (!res.ok) { toast("Export failed", "err"); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    toast(`Downloaded ${filename}`);
  } catch (e) { toast(e.message, "err"); }
}

// ---------------- Reference view ----------------
async function viewReference() {
  const m = $main();
  const [ref, tactics, topos, roles, fw] = await Promise.all([
    api("GET", "/reference"), api("GET", "/tactics"), api("GET", "/topologies"),
    api("GET", "/roles"), api("GET", "/frameworks"),
  ]);
  const fwt = fw.techniques || {};
  m.innerHTML = `
    <h3>Roles &amp; permissions - what each role can do</h3>
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
    <h3>Framework alignment <span class="faint" style="font-size:11px;text-transform:none">(curated crosswalk from ATT&amp;CK to ${esc(fw.frameworks.nist_csf.name)}, NICE, CIS v8, NSA CAE)</span></h3>
    <div class="table-wrap"><table><thead><tr><th>ATT&CK</th><th>NIST CSF</th><th>NICE work roles</th><th>CIS Controls</th><th>NSA CAE KUs</th></tr></thead>
      <tbody>${Object.keys(fwt).sort().map(tid => { const e = fwt[tid]; return `<tr>
        <td class="mono">${esc(tid)}</td>
        <td>${(e.nist_csf||[]).map(x=>`<span class="tag">${esc(x)}</span>`).join(" ")}</td>
        <td class="muted">${(e.nice||[]).join(", ")}</td>
        <td class="muted">${(e.cis||[]).join(", ")}</td>
        <td class="muted">${(e.cae||[]).join(", ")}</td></tr>`; }).join("")}</tbody></table></div>
    <p class="faint" style="font-size:11.5px">${esc(fw._note)}</p>
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
  m.innerHTML = `
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
    m.innerHTML = `<p class="muted">Your role (${esc(session.role)}) cannot manage users.</p>`;
    return;
  }
  m.innerHTML = `
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

// ---------------- Classes (instructor) ----------------
async function viewClasses() {
  const m = $main();
  m.innerHTML = `
    <div class="toolbar">
      <input id="new-class" placeholder="New class name, e.g. Intro to Cyber - Fall" style="min-width:280px" />
      <button class="act" id="btn-new-class">＋ Create class</button>
    </div>
    <div class="grid" id="class-cards"></div>`;
  document.getElementById("btn-new-class").onclick = async () => {
    const name = document.getElementById("new-class").value.trim();
    if (!name) return;
    try { await api("POST", "/cohorts", { name }); toast("Class created"); viewClasses(); }
    catch (e) { toast(e.message, "err"); }
  };
  const classes = await api("GET", "/cohorts");
  const wrap = document.getElementById("class-cards");
  if (!classes.length) { wrap.innerHTML = `<p class="muted">No classes yet - create one above.</p>`; return; }
  classes.forEach((c) => {
    const card = el(`<div class="card">
      <h4>${esc(c.name)}</h4>
      <p class="muted" style="font-size:12.5px">${c.member_count} students · ${c.assignment_count} lessons assigned</p>
      <button class="act" data-class="${esc(c.id)}" style="margin-top:8px">Open →</button></div>`);
    card.querySelector("[data-class]").onclick = () => openClass(c.id);
    wrap.appendChild(card);
  });
}

async function openClass(cid) {
  const m = $main();
  const [c, scenarios] = await Promise.all([
    api("GET", `/cohorts/${cid}`), api("GET", "/scenarios"),
  ]);
  const lessons = scenarios.filter((s) => s.learning);
  m.innerHTML = `
    <div class="toolbar"><button class="ghost" id="cback">← Classes</button></div>
    <h2>${esc(c.name)}</h2>
    <div class="split">
      <div>
        <div class="panel">
          <div class="phead">Enroll students</div>
          <div class="phelp">Paste a CSV: <span class="mono">username,display name,password</span> (one per line; password optional - we'll generate one).</div>
          <textarea id="roster-csv" rows="4" style="width:100%" placeholder="alice,Alice Ng&#10;bob,Bob Lee,bobpass123"></textarea>
          <button class="ghost" id="btn-import" style="margin-top:8px">Import roster</button>
          <div id="import-out" style="margin-top:8px;font-size:12px"></div>
        </div>
        <div class="panel">
          <div class="phead">Assign a lesson</div>
          <div class="row"><select id="asn-scenario" style="flex:1">
            ${lessons.map(s => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join("")}</select>
            <button class="act" id="btn-assign">Assign</button></div>
        </div>
        <div class="panel">
          <div class="phead">Students (${c.members.length})</div>
          <div id="member-list">${c.members.map(mm => `<div class="row" style="justify-content:space-between;padding:4px 0">
            <span>${esc(mm.display_name || mm.username)} <span class="faint mono">${esc(mm.username)}</span></span>
            <span class="tag">${esc(mm.role)}</span></div>`).join("") || '<span class="muted">No students yet.</span>'}</div>
        </div>
      </div>
      <div>
        <div class="row" style="justify-content:space-between;align-items:baseline">
          <h3 style="margin:0">Gradebook</h3>
          <span class="row" style="gap:6px">
            <button class="ghost" id="btn-gb-csv" style="padding:5px 10px">Export CSV</button>
            <button class="ghost" id="btn-gb" style="padding:5px 10px">↻</button></span></div>
        <div id="gradebook"></div>
      </div>
    </div>`;
  document.getElementById("cback").onclick = () => switchView("classes");
  document.getElementById("btn-import").onclick = async () => {
    const csv = document.getElementById("roster-csv").value;
    if (!csv.trim()) return;
    try {
      const r = await api("POST", `/cohorts/${cid}/roster`, { csv });
      const creds = r.credentials.length
        ? "<br>Generated logins:<br>" + r.credentials.map(x => `<span class="mono">${esc(x.username)} / ${esc(x.password)}</span>`).join("<br>")
        : "";
      document.getElementById("import-out").innerHTML =
        `<span style="color:var(--green)">Created ${r.created}, enrolled ${r.enrolled}.</span>${creds}`;
      openClass(cid);
    } catch (e) { toast(e.message, "err"); }
  };
  document.getElementById("btn-assign").onclick = async () => {
    try {
      await api("POST", `/cohorts/${cid}/assignments`, { scenario_id: document.getElementById("asn-scenario").value });
      toast("Lesson assigned"); openClass(cid);
    } catch (e) { toast(e.message, "err"); }
  };
  document.getElementById("btn-gb").onclick = () => loadGradebook(cid);
  document.getElementById("btn-gb-csv").onclick = () =>
    downloadFile(`/cohorts/${cid}/gradebook.csv`, `gradebook-${cid}.csv`);
  await loadGradebook(cid);
}

async function loadGradebook(cid) {
  const gb = await api("GET", `/cohorts/${cid}/gradebook`);
  const box = document.getElementById("gradebook");
  if (!gb.assignments.length) { box.innerHTML = `<p class="muted">Assign a lesson to start tracking progress.</p>`; return; }
  if (!gb.rows.length) { box.innerHTML = `<p class="muted">Enroll students to see the gradebook.</p>`; return; }
  const head = gb.assignments.map(a => `<th title="${esc(a.title)}">${esc((a.title || "").slice(0, 14))}</th>`).join("");
  const rows = gb.rows.map(r => `<tr>
    <td><strong>${esc(r.display_name || r.username)}</strong></td>
    ${gb.assignments.map(a => {
      const c = r.cells[a.id] || {};
      const v = c.status === "completed" ? `<span class="tag s0">${c.score == null ? "done" : c.score + "%"}</span>`
        : (c.status === "in_progress" ? `<span class="tag s1">${c.steps_done ? c.steps_done.length : 0}/${c.total_steps}</span>` : `<span class="faint">-</span>`);
      return `<td>${v}</td>`;
    }).join("")}
    <td>${r.avg_score == null ? "-" : "<strong>" + r.avg_score + "%</strong>"}</td></tr>`).join("");
  box.innerHTML = `<div class="table-wrap"><table>
    <thead><tr><th>Student</th>${head}<th>Avg</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

// ---------------- Router ----------------
const VIEWS = {
  catalog: viewCatalog, ranges: viewRanges, exercise: viewExercise,
  reference: viewReference, audit: viewAudit, admin: viewAdmin,
  classes: viewClasses,
};

/* Kept short: the page title already names the section, so this line says what
   you do here, not what it is called. */
const VIEW_HELP = {
  classes: "Create a class, enrol students, assign lessons, and track progress in the gradebook.",
  catalog: "Browse what the lab can run. Launch a scenario to create an isolated range.",
  ranges: "Prepare a range through its lifecycle, then start the exercise. Every range is isolated, with no internet access.",
  exercise: "The live lab. Your panels follow your role: red launches attacks, blue hunts the logs they leave behind.",
  reference: "ATT&amp;CK coverage, the scoring model, safety classes, the detection stack, topologies, and what each role can do.",
  audit: "An append-only ledger of every action, attributed to a user and a role.",
  admin: "Provision user accounts and assign each one a role.",
};

const VIEW_TITLES = {
  classes: "Classes", catalog: "Catalog", ranges: "Ranges", exercise: "Exercise",
  reference: "Reference", audit: "Audit", admin: "Admin",
};

function switchView(name) {
  state.view = name;
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.view === name));
  document.getElementById("view-title").textContent = VIEW_TITLES[name] || name;
  document.getElementById("view-help").innerHTML = VIEW_HELP[name] || "";
  $main().innerHTML = "";
  VIEWS[name]().catch((e) => {
    $main().innerHTML = emptyState("⚠", "Could not load this view", esc(e.message));
  });
}

/* The view a user lands on should be the one their role actually works in:
   launchers start in the catalog, participants in the live exercise, and
   read-only oversight in the reference material. */
function defaultView() {
  if (can("range:create")) return "catalog";
  if (can("exercise:participate")) return "exercise";
  return "reference";
}

function emptyState(icon, title, body, action = "") {
  return `<div class="empty">
    <span class="ico">${icon}</span>
    <strong>${title}</strong>
    <p>${body}</p>
    ${action}
  </div>`;
}

// ---------------- Theme ----------------
const THEME_KEY = "cr_theme";

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* private mode */ }
}

function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch { /* private mode */ }
  applyTheme(saved || "dark");
  document.getElementById("btn-theme").addEventListener("click", () => {
    applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
  });
}

// Whether live execution is currently available. A module runs for real only
// when it carries an execution spec AND a Docker daemon is reachable; otherwise
// it falls back to simulation. The catalog and the attack console read this so
// an operator knows which it will get before launching.
const execState = { real: false, mode: "simulated" };

function moduleIsRealCapable(m) {
  // Only Linux/Docker modules ship an execution spec; Windows modules never do.
  return Boolean(m.execution);
}
function moduleWillRunReal(m) {
  return moduleIsRealCapable(m) && execState.real;
}

async function checkHealth() {
  const pill = document.getElementById("health");
  try {
    const h = await api("GET", "/health");
    execState.real = Boolean(h.execution && h.execution.real);
    execState.mode = (h.execution && h.execution.mode) || "simulated";
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
  document.getElementById("tab-classes").hidden = !can("cohort:manage");
  // The ledger names the modules red executed, so it must not be an exit from
  // the defender's redacted view. NOTE: GET /api/audit does not yet enforce
  // admin:audit server-side (see docs/TESTING.md) - hiding the tab is not the
  // fix, only the correct UI behaviour alongside it.
  document.getElementById("tab-audit").hidden = !can("admin:audit");
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
    switchView(defaultView());
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
  initTheme();
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
      switchView(defaultView());
      checkHealth();
      setInterval(checkHealth, 15000);
      return;
    } catch { clearSession(); }
  }
  showLogin();
}

bootstrap();
