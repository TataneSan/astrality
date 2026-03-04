const state = {
  token: localStorage.getItem('token') || 'dev-admin',
  selectedNode: null,
};

const tokenInput = document.getElementById('token');
const saveTokenBtn = document.getElementById('saveToken');
const refreshBtn = document.getElementById('refresh');
const nodesBody = document.querySelector('#nodesTable tbody');
const nodeTitle = document.getElementById('nodeTitle');
const nodeMeta = document.getElementById('nodeMeta');
const logsPre = document.getElementById('logs');
const consolePre = document.getElementById('console');
const openConsoleBtn = document.getElementById('openConsole');
const revokeNodeBtn = document.getElementById('revokeNode');
const canvas = document.getElementById('chart');
const jobCommandInput = document.getElementById('jobCommand');
const jobArgsInput = document.getElementById('jobArgs');
const jobSelectorInput = document.getElementById('jobSelector');
const createJobBtn = document.getElementById('createJob');
const jobsBody = document.querySelector('#jobsTable tbody');
const jobRunsPre = document.getElementById('jobRuns');

function authHeaders() {
  return { Authorization: `Bearer ${state.token}` };
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(opts.headers || {}),
    },
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const d = await res.json();
      msg = d.error || msg;
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

function fmtDate(v) {
  if (!v) return '-';
  return new Date(v).toLocaleString();
}

function renderNodes(items) {
  nodesBody.innerHTML = '';
  for (const n of items) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${n.hostname}</td>
      <td class="status-${n.status}">${n.status}</td>
      <td>${n.ip}</td>
      <td>${n.cpu_usage.toFixed(1)}</td>
      <td>${n.mem_usage.toFixed(1)}</td>
      <td>${n.disk_usage.toFixed(1)}</td>
      <td>${fmtDate(n.last_seen)}</td>
    `;
    tr.onclick = () => selectNode(n.id);
    nodesBody.appendChild(tr);
  }
}

function drawSeries(series) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  ctx.strokeStyle = '#d8dee4';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 5; i++) {
    const y = (h / 5) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  if (!series.length) return;
  const max = 100;
  const step = w / Math.max(1, series.length - 1);

  ctx.strokeStyle = '#0f5ea8';
  ctx.lineWidth = 2;
  ctx.beginPath();
  series.forEach((v, i) => {
    const x = i * step;
    const y = h - (v / max) * h;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

async function refreshNodes() {
  const data = await api('/api/v1/nodes');
  renderNodes(data.items || []);
  await refreshJobs();
}

async function selectNode(id) {
  state.selectedNode = id;
  const detail = await api(`/api/v1/nodes/${id}`);
  nodeTitle.textContent = `Machine Detail: ${detail.node.hostname}`;
  nodeMeta.innerHTML = `
    <div>ID: ${detail.node.id}</div>
    <div>Status: ${detail.node.status}</div>
    <div>OS: ${detail.node.os}/${detail.node.arch}</div>
    <div>IP: ${detail.node.ip}</div>
    <div>Agent: ${detail.node.agent_version || '-'}</div>
    <div>Seen: ${fmtDate(detail.node.last_seen)}</div>
  `;

  const hb = await api(`/api/v1/nodes/${id}/heartbeats?limit=60`);
  const series = (hb.items || []).slice().reverse().map((x) => x.cpu_usage || 0);
  drawSeries(series);

  const logs = await api(`/api/v1/nodes/${id}/logs?limit=80`);
  logsPre.textContent = (logs.items || [])
    .slice()
    .reverse()
    .map((l) => `[${fmtDate(l.ts)}] ${l.level} ${l.message}`)
    .join('\n');

  consolePre.textContent = '';
}

async function openConsole() {
  if (!state.selectedNode) return;
  const out = await api(`/api/v1/nodes/${state.selectedNode}/console/session`, { method: 'POST', body: '{}' });
  consolePre.textContent = out.ssh_command;
}

async function revokeNode() {
  if (!state.selectedNode) return;
  await api(`/api/v1/nodes/${state.selectedNode}/revoke`, { method: 'POST', body: '{}' });
  await refreshNodes();
  await selectNode(state.selectedNode);
}

function renderJobs(items) {
  jobsBody.innerHTML = '';
  for (const j of items) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${j.id}</td>
      <td>${j.command} ${(j.args || []).join(' ')}</td>
      <td class="status-${j.status}">${j.status}</td>
      <td>${j.node_selector}</td>
      <td>${j.created_by}</td>
      <td>${fmtDate(j.updated_at)}</td>
    `;
    tr.onclick = () => selectJob(j.id);
    jobsBody.appendChild(tr);
  }
}

async function refreshJobs() {
  const data = await api('/api/v2/jobs?limit=50');
  renderJobs(data.items || []);
}

async function selectJob(id) {
  const data = await api(`/api/v2/jobs/${id}`);
  const runs = data.runs || [];
  jobRunsPre.textContent = runs
    .map((r) => `${r.node_id} ${r.status} attempt=${r.attempt} exit=${r.exit_code ?? '-'}\nstdout:\n${r.stdout || ''}\nstderr:\n${r.stderr || ''}`)
    .join('\n\n---\n\n');
}

async function createJob() {
  const command = jobCommandInput.value.trim();
  if (!command) return;
  const args = jobArgsInput.value.trim() ? jobArgsInput.value.trim().split(/\s+/) : [];
  const nodeSelector = jobSelectorInput.value.trim() || 'all';
  await api('/api/v2/jobs', {
    method: 'POST',
    body: JSON.stringify({
      command,
      args,
      node_selector: nodeSelector,
      timeout_sec: 60,
      max_retries: 0,
    }),
  });
  jobCommandInput.value = '';
  jobArgsInput.value = '';
  await refreshJobs();
}

saveTokenBtn.onclick = async () => {
  state.token = tokenInput.value.trim();
  localStorage.setItem('token', state.token);
  await refreshNodes();
};
refreshBtn.onclick = async () => refreshNodes();
openConsoleBtn.onclick = async () => openConsole();
revokeNodeBtn.onclick = async () => revokeNode();
createJobBtn.onclick = async () => createJob();

tokenInput.value = state.token;
refreshNodes().catch((e) => {
  nodesBody.innerHTML = `<tr><td colspan="7">${e.message}</td></tr>`;
});
