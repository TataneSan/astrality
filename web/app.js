const state = {
  token: localStorage.getItem("token") || "",
  refreshToken: localStorage.getItem("refresh_token") || "",
  tokenExpMs: Number(localStorage.getItem("token_exp_ms") || "0"),
  authEnabled: false,
  authIssuer: "",
  authClientID: "",
  authUser: localStorage.getItem("auth_user") || "",
  refreshInFlight: null,
  selectedNode: null,
  nodes: [],
  nodeFilter: "",
  autoRefreshSec: Number(localStorage.getItem("auto_refresh_sec") || "10"),
  refreshTimer: null,
  liveWs: null,
  liveSessionId: null,
};

const tokenInput = document.getElementById("token");
const saveTokenBtn = document.getElementById("saveToken");
const refreshBtn = document.getElementById("refresh");
const loginUserInput = document.getElementById("loginUser");
const loginPassInput = document.getElementById("loginPass");
const loginBtn = document.getElementById("loginBtn");
const logoutBtn = document.getElementById("logoutBtn");
const authState = document.getElementById("authState");
const nodeFilterInput = document.getElementById("nodeFilter");
const autoRefreshSelect = document.getElementById("autoRefreshSec");
const banner = document.getElementById("errorBanner");

const metricTotal = document.getElementById("metricTotal");
const metricOnline = document.getElementById("metricOnline");
const metricDegraded = document.getElementById("metricDegraded");
const metricOffline = document.getElementById("metricOffline");
const metricRevoked = document.getElementById("metricRevoked");

const nodesBody = document.querySelector("#nodesTable tbody");
const nodeTitle = document.getElementById("nodeTitle");
const nodeMeta = document.getElementById("nodeMeta");
const logsPre = document.getElementById("logs");
const consolePre = document.getElementById("console");
const liveStatus = document.getElementById("liveStatus");
const openConsoleBtn = document.getElementById("openConsole");
const closeLiveBtn = document.getElementById("closeLive");
const revokeNodeBtn = document.getElementById("revokeNode");
const liveInput = document.getElementById("liveInput");
const canvas = document.getElementById("chart");

const jobCommandInput = document.getElementById("jobCommand");
const jobArgsInput = document.getElementById("jobArgs");
const jobSelectorInput = document.getElementById("jobSelector");
const createJobBtn = document.getElementById("createJob");
const jobsBody = document.querySelector("#jobsTable tbody");
const jobRunsPre = document.getElementById("jobRuns");
const alertsBody = document.querySelector("#alertsTable tbody");
const timelineBody = document.querySelector("#timelineTable tbody");

function setAuthState(text) {
  authState.textContent = text;
}

function saveSession() {
  if (state.token) localStorage.setItem("token", state.token);
  else localStorage.removeItem("token");

  if (state.refreshToken) localStorage.setItem("refresh_token", state.refreshToken);
  else localStorage.removeItem("refresh_token");

  if (state.tokenExpMs > 0) localStorage.setItem("token_exp_ms", String(state.tokenExpMs));
  else localStorage.removeItem("token_exp_ms");

  if (state.authUser) localStorage.setItem("auth_user", state.authUser);
  else localStorage.removeItem("auth_user");
}

function clearSession() {
  state.token = "";
  state.refreshToken = "";
  state.tokenExpMs = 0;
  state.authUser = "";
  saveSession();
}

function authHeaders() {
  if (!state.token) return {};
  return { Authorization: `Bearer ${state.token}` };
}

function decodeJWTExpMS(token) {
  try {
    const payload = token.split(".")[1];
    if (!payload) return 0;
    const padded = payload + "=".repeat((4 - (payload.length % 4)) % 4);
    const json = JSON.parse(atob(padded.replace(/-/g, "+").replace(/_/g, "/")));
    if (!json.exp) return 0;
    return Number(json.exp) * 1000;
  } catch {
    return 0;
  }
}

function updateSessionFromTokenPayload(payload) {
  const nextToken = String(payload.id_token || payload.access_token || "").trim();
  if (nextToken) state.token = nextToken;
  if (payload.refresh_token) state.refreshToken = payload.refresh_token;
  const expiresIn = Number(payload.expires_in || 0);
  if (expiresIn > 0) {
    state.tokenExpMs = Date.now() + expiresIn * 1000;
  } else {
    state.tokenExpMs = decodeJWTExpMS(state.token);
  }
  saveSession();
  tokenInput.value = state.token;
}

function unauthorizedHelp() {
  if (state.authEnabled) {
    return "Unauthorized: session expirée ou invalide. Reconnecte-toi avec Login.";
  }
  return [
    "Unauthorized: token invalide ou expiré.",
    "Génération rapide:",
    "source /etc/astrality/bootstrap-admin.env",
    "curl -sS -X POST \"$OIDC_TOKEN_URL\" -H 'Content-Type: application/x-www-form-urlencoded' \\",
    "  --data-urlencode 'grant_type=password' --data-urlencode \"client_id=$OIDC_CLIENT_ID\" \\",
    "  --data-urlencode \"username=$OIDC_USERNAME\" --data-urlencode \"password=$OIDC_PASSWORD\" \\",
    "  --data-urlencode 'scope=openid profile email' | jq -r .id_token",
  ].join("\n");
}

function showError(err) {
  const msg = err instanceof Error ? err.message : String(err);
  banner.textContent = msg;
  banner.classList.remove("hidden");
}

function clearError() {
  banner.textContent = "";
  banner.classList.add("hidden");
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

async function rawJSON(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, { ...opts, headers });
  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  if (!res.ok) {
    const msg = (body && body.error) || res.statusText || `http ${res.status}`;
    throw new Error(msg);
  }
  return body;
}

async function refreshOIDCToken() {
  if (!state.refreshToken) {
    throw new Error("no refresh token");
  }
  const payload = await rawJSON("/api/v1/auth/refresh", {
    method: "POST",
    body: JSON.stringify({ refresh_token: state.refreshToken }),
  });
  updateSessionFromTokenPayload(payload || {});
}

async function ensureTokenFresh() {
  if (!state.token || !state.refreshToken || !state.tokenExpMs) return;
  if (Date.now() < state.tokenExpMs - 45000) return;
  if (state.refreshInFlight) {
    await state.refreshInFlight;
    return;
  }
  state.refreshInFlight = (async () => {
    await refreshOIDCToken();
  })();
  try {
    await state.refreshInFlight;
  } finally {
    state.refreshInFlight = null;
  }
}

async function api(path, opts = {}, allowRetry = true) {
  await ensureTokenFresh();
  const headers = {
    ...authHeaders(),
    ...(opts.headers || {}),
  };
  if (opts.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, { ...opts, headers });
  if (!res.ok) {
    if (res.status === 401 && allowRetry && state.refreshToken) {
      try {
        await refreshOIDCToken();
        return api(path, opts, false);
      } catch {}
    }
    if (res.status === 401) {
      clearSession();
      setAuthState("auth: disconnected");
      throw new Error(unauthorizedHelp());
    }
    let msg = res.statusText;
    try {
      const d = await res.json();
      msg = d.error || msg;
    } catch {}
    throw new Error(msg || `http ${res.status}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

function fmtDate(v) {
  if (!v) return "-";
  return new Date(v).toLocaleString();
}

function setLiveStatus(text) {
  liveStatus.textContent = text;
}

function updateMetrics(items) {
  const counts = { online: 0, degraded: 0, offline: 0, revoked: 0 };
  for (const n of items) {
    if (counts[n.status] !== undefined) counts[n.status] += 1;
  }
  metricTotal.textContent = String(items.length);
  metricOnline.textContent = String(counts.online);
  metricDegraded.textContent = String(counts.degraded);
  metricOffline.textContent = String(counts.offline);
  metricRevoked.textContent = String(counts.revoked);
}

function filteredNodes() {
  const q = state.nodeFilter.trim().toLowerCase();
  if (!q) return state.nodes;
  return state.nodes.filter((n) =>
    `${n.hostname} ${n.ip} ${n.status}`.toLowerCase().includes(q)
  );
}

function renderNodes(items) {
  nodesBody.innerHTML = "";
  if (!items.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="7">no nodes</td>`;
    nodesBody.appendChild(tr);
    return;
  }
  for (const n of items) {
    const tr = document.createElement("tr");
    if (state.selectedNode === n.id) tr.classList.add("selected");
    tr.innerHTML = `
      <td>${n.hostname}</td>
      <td class="status-${n.status}">${n.status}</td>
      <td>${n.ip}</td>
      <td>${num(n.cpu_usage).toFixed(1)}</td>
      <td>${num(n.mem_usage).toFixed(1)}</td>
      <td>${num(n.disk_usage).toFixed(1)}</td>
      <td>${fmtDate(n.last_seen)}</td>
    `;
    tr.onclick = () => run(() => selectNode(n.id));
    nodesBody.appendChild(tr);
  }
}

function drawSeries(series) {
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  ctx.strokeStyle = "#d8dee4";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 5; i++) {
    const y = (h / 5) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  if (!series.length) return;
  const step = w / Math.max(1, series.length - 1);
  ctx.strokeStyle = "#0062b8";
  ctx.lineWidth = 2;
  ctx.beginPath();
  series.forEach((v, i) => {
    const x = i * step;
    const y = h - (Math.max(0, Math.min(100, num(v))) / 100) * h;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

async function refreshNodesOnly() {
  const data = await api("/api/v1/nodes");
  state.nodes = data.items || [];
  updateMetrics(state.nodes);
  renderNodes(filteredNodes());
  if (state.selectedNode && !state.nodes.some((n) => n.id === state.selectedNode)) {
    state.selectedNode = null;
    nodeTitle.textContent = "Machine Detail";
    nodeMeta.innerHTML = "";
    logsPre.textContent = "";
    consolePre.textContent = "";
    drawSeries([]);
  }
}

async function selectNode(id) {
  state.selectedNode = id;
  renderNodes(filteredNodes());

  const detail = await api(`/api/v1/nodes/${id}`);
  const node = detail.node || {};
  nodeTitle.textContent = node.hostname ? `Machine Detail: ${node.hostname}` : "Machine Detail";
  nodeMeta.innerHTML = `
    <div>ID: ${node.id || "-"}</div>
    <div>Status: ${node.status || "-"}</div>
    <div>OS: ${node.os || "-"}/${node.arch || "-"}</div>
    <div>IP: ${node.ip || "-"}</div>
    <div>Agent: ${node.agent_version || "-"}</div>
    <div>Seen: ${fmtDate(node.last_seen)}</div>
  `;

  const [hb, logs] = await Promise.all([
    api(`/api/v1/nodes/${id}/heartbeats?limit=60`),
    api(`/api/v1/nodes/${id}/logs?limit=80`),
  ]);
  const series = (hb.items || []).slice().reverse().map((x) => num(x.cpu_usage));
  drawSeries(series);
  logsPre.textContent = (logs.items || [])
    .slice()
    .reverse()
    .map((l) => `[${fmtDate(l.ts)}] ${l.level} ${l.message}`)
    .join("\n");
}

function appendConsole(chunk) {
  consolePre.textContent += chunk;
  if (consolePre.textContent.length > 300000) {
    consolePre.textContent = consolePre.textContent.slice(-200000);
  }
  consolePre.scrollTop = consolePre.scrollHeight;
}

function closeLiveSocketOnly() {
  if (state.liveWs) {
    state.liveWs.close();
    state.liveWs = null;
  }
}

function buildWebSocketURL(path) {
  if (path.startsWith("ws://") || path.startsWith("wss://")) return path;
  const proto = window.location.protocol === "https:" ? "wss://" : "ws://";
  return `${proto}${window.location.host}${path}`;
}

async function openConsole() {
  if (!state.selectedNode) throw new Error("select a node");
  const reason = (prompt("Reason") || "").trim();
  if (!reason) return;

  await closeLive();
  const out = await api("/api/v2/console/sessions", {
    method: "POST",
    body: JSON.stringify({ node_id: state.selectedNode, reason }),
  });
  const wsUrl = buildWebSocketURL(out.ws_url);
  setLiveStatus("console: connecting");
  consolePre.textContent = "";
  state.liveSessionId = out.session.id;
  state.liveWs = new WebSocket(wsUrl);
  state.liveWs.binaryType = "arraybuffer";

  state.liveWs.onopen = () => {
    setLiveStatus("console: connected");
  };
  state.liveWs.onmessage = (evt) => {
    const text =
      typeof evt.data === "string"
        ? evt.data
        : new TextDecoder().decode(new Uint8Array(evt.data));
    appendConsole(text);
  };
  state.liveWs.onerror = () => {
    setLiveStatus("console: error");
    showError(new Error("websocket error"));
  };
  state.liveWs.onclose = () => {
    setLiveStatus("console: closed");
  };
}

async function closeLive() {
  if (state.liveSessionId) {
    try {
      await api(`/api/v2/console/sessions/${state.liveSessionId}/close`, {
        method: "POST",
        body: "{}",
      });
    } catch {}
  }
  closeLiveSocketOnly();
  state.liveSessionId = null;
  setLiveStatus("console: closed");
}

async function revokeNode() {
  if (!state.selectedNode) throw new Error("select a node");
  await api(`/api/v1/nodes/${state.selectedNode}/revoke`, { method: "POST", body: "{}" });
  await refreshAll();
}

function renderJobs(items) {
  jobsBody.innerHTML = "";
  for (const j of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${j.id}</td>
      <td>${j.command} ${(j.args || []).join(" ")}</td>
      <td class="status-${j.status}">${j.status}</td>
      <td>${j.node_selector}</td>
      <td>${j.created_by}</td>
      <td>${fmtDate(j.updated_at)}</td>
    `;
    tr.onclick = () => run(() => selectJob(j.id));
    jobsBody.appendChild(tr);
  }
}

async function refreshJobs() {
  const data = await api("/api/v2/jobs?limit=50");
  renderJobs(data.items || []);
}

async function selectJob(id) {
  const data = await api(`/api/v2/jobs/${id}`);
  const runs = data.runs || [];
  jobRunsPre.textContent = runs
    .map((r) => `${r.node_id} ${r.status} attempt=${r.attempt} exit=${r.exit_code ?? "-"}\nstdout:\n${r.stdout || ""}\nstderr:\n${r.stderr || ""}`)
    .join("\n\n---\n\n");
}

async function createJob() {
  const command = jobCommandInput.value.trim();
  if (!command) throw new Error("command required");
  const args = jobArgsInput.value.trim() ? jobArgsInput.value.trim().split(/\s+/) : [];
  const nodeSelector = jobSelectorInput.value.trim() || "all";
  await api("/api/v2/jobs", {
    method: "POST",
    body: JSON.stringify({
      command,
      args,
      node_selector: nodeSelector,
      timeout_sec: 60,
      max_retries: 0,
    }),
  });
  jobCommandInput.value = "";
  jobArgsInput.value = "";
  await refreshJobs();
}

function renderAlerts(items) {
  alertsBody.innerHTML = "";
  for (const a of items) {
    const tr = document.createElement("tr");
    const btn = a.status === "open" ? `<button data-ack="${a.id}">Ack</button>` : "";
    tr.innerHTML = `
      <td>${a.id}</td>
      <td>${a.severity}</td>
      <td class="status-${a.status}">${a.status}</td>
      <td>${a.message}</td>
      <td>${fmtDate(a.opened_at)}</td>
      <td>${btn}</td>
    `;
    alertsBody.appendChild(tr);
  }
  for (const b of alertsBody.querySelectorAll("button[data-ack]")) {
    b.onclick = () => run(async () => {
      await api(`/api/v2/alerts/events/${b.dataset.ack}/ack`, { method: "POST", body: "{}" });
      await refreshAlerts();
    });
  }
}

async function refreshAlerts() {
  const data = await api("/api/v2/alerts/events?limit=50");
  renderAlerts(data.items || []);
}

function renderTimeline(items) {
  timelineBody.innerHTML = "";
  for (const t of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${fmtDate(t.ts)}</td>
      <td>${t.kind}</td>
      <td>${t.severity}</td>
      <td>${t.actor}</td>
      <td>${t.message}</td>
    `;
    timelineBody.appendChild(tr);
  }
}

async function refreshTimeline() {
  const data = await api("/api/v2/incidents/timeline?limit=100");
  renderTimeline(data.items || []);
}

async function refreshAll() {
  clearError();
  if (!state.token) {
    return;
  }
  await refreshNodesOnly();
  await Promise.all([refreshJobs(), refreshAlerts(), refreshTimeline()]);
  if (state.selectedNode) {
    await selectNode(state.selectedNode);
  }
}

function resetAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
  const sec = Number(state.autoRefreshSec);
  if (sec > 0) {
    state.refreshTimer = setInterval(() => {
      run(() => refreshAll());
    }, sec * 1000);
  }
}

async function loginWithPassword() {
  if (!state.authEnabled) {
    throw new Error("login OIDC indisponible sur ce serveur");
  }
  const username = loginUserInput.value.trim();
  const password = loginPassInput.value;
  if (!username || !password) {
    throw new Error("username and password are required");
  }
  const payload = await rawJSON("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  state.authUser = username;
  updateSessionFromTokenPayload(payload || {});
  loginPassInput.value = "";
  setAuthState(`auth: connected (${username})`);
  await refreshAll();
}

async function logout() {
  await closeLive();
  clearSession();
  tokenInput.value = "";
  loginPassInput.value = "";
  setAuthState("auth: disconnected");
}

async function initAuthConfig() {
  try {
    const cfg = await rawJSON("/api/v1/auth/config");
    state.authEnabled = !!(cfg && cfg.enabled);
    state.authIssuer = (cfg && cfg.issuer) || "";
    state.authClientID = (cfg && cfg.client_id) || "";
  } catch {
    state.authEnabled = false;
  }
  if (state.authEnabled) {
    loginUserInput.disabled = false;
    loginPassInput.disabled = false;
    loginBtn.disabled = false;
    if (state.token && state.authUser) {
      loginUserInput.value = state.authUser;
      setAuthState(`auth: cached (${state.authUser})`);
    } else if (state.token) {
      setAuthState("auth: token loaded");
    } else {
      setAuthState("auth: disconnected");
    }
  } else {
    loginUserInput.disabled = true;
    loginPassInput.disabled = true;
    loginBtn.disabled = true;
    setAuthState("auth: token mode");
  }
}

async function run(fn) {
  try {
    await fn();
  } catch (err) {
    showError(err);
  }
}

saveTokenBtn.onclick = () => run(async () => {
  state.token = tokenInput.value.trim();
  state.refreshToken = "";
  state.tokenExpMs = decodeJWTExpMS(state.token);
  saveSession();
  if (state.token) {
    setAuthState("auth: token loaded");
  } else {
    setAuthState("auth: disconnected");
  }
  await refreshAll();
});

loginBtn.onclick = () => run(() => loginWithPassword());
logoutBtn.onclick = () => run(() => logout());
refreshBtn.onclick = () => run(() => refreshAll());
openConsoleBtn.onclick = () => run(() => openConsole());
closeLiveBtn.onclick = () => run(() => closeLive());
revokeNodeBtn.onclick = () => run(() => revokeNode());
createJobBtn.onclick = () => run(() => createJob());
loginUserInput.onkeydown = (e) => {
  if (e.key === "Enter") run(() => loginWithPassword());
};
loginPassInput.onkeydown = (e) => {
  if (e.key === "Enter") run(() => loginWithPassword());
};

nodeFilterInput.oninput = () => {
  state.nodeFilter = nodeFilterInput.value;
  renderNodes(filteredNodes());
};

autoRefreshSelect.onchange = () => {
  state.autoRefreshSec = Number(autoRefreshSelect.value || "0");
  localStorage.setItem("auto_refresh_sec", String(state.autoRefreshSec));
  resetAutoRefresh();
};

liveInput.onkeydown = (e) => {
  if (e.key !== "Enter") return;
  if (!state.liveWs || state.liveWs.readyState !== WebSocket.OPEN) return;
  const value = liveInput.value;
  if (!value.trim()) return;
  state.liveWs.send(`${value}\n`);
  liveInput.value = "";
};

tokenInput.value = state.token;
nodeFilterInput.value = state.nodeFilter;
autoRefreshSelect.value = String(state.autoRefreshSec);
setLiveStatus("console: closed");
resetAutoRefresh();

run(async () => {
  await initAuthConfig();
  if (!state.token) return;
  await refreshAll();
});
