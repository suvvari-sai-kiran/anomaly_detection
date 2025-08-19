 // ---------------- Utility ----------------
function apiBase() {
  const u = document.getElementById('apiUrl').value.trim();
  return u || '';
}

async function fetchJson(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// ---------------- Main Data Loader ----------------
async function loadData() {
  const base = apiBase();
  const flows = await fetchJson(`${base}/flows`);
  const blocked = await fetchJson(`${base}/blocked`);
  renderFlows(flows);
  renderBlocked(blocked);
  renderCharts(flows);
}

// ---------------- Table Renderers ----------------
function renderFlows(rows) {
  let html = '<table><tr><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>Pkts</th><th>Bytes</th><th>Anom</th><th>Action</th></tr>';
  rows.forEach(r => {
    const anomalyClass = r.is_anomaly == 1 ? 'anom-row' : 'ok-row';
    html += `<tr class="${anomalyClass}">
      <td>${r.ts ?? ''}</td>
      <td>${r.src_ip ?? ''}</td>
      <td>${r.dest_ip ?? ''}</td>
      <td>${r.protocol ?? ''}</td>
      <td>${r.packets ?? ''}</td>
      <td>${r.bytes_sent ?? ''}</td>
      <td>${r.is_anomaly==1 ? '<span class="badge anom">YES</span>' : '<span class="badge ok">NO</span>'}</td>
      <td>${r.action_taken ?? ''}</td>
    </tr>`;
  });
  html += '</table>';
  document.getElementById('flows').innerHTML = html;
}

function renderBlocked(rows) {
  let html = '<table><tr><th>IP</th><th>Blocked At</th><th>Device</th><th>Reason</th><th></th></tr>';
  rows.forEach(r => {
    html += `<tr>
      <td>${r.ip ?? ''}</td>
      <td>${r.blocked_at ?? ''}</td>
      <td>${r.device ?? ''}</td>
      <td>${r.reason ?? ''}</td>
      <td><button onclick="unblock('${r.ip}')">Unblock</button></td>
    </tr>`;
  });
  html += '</table>';
  document.getElementById('blocked').innerHTML = html;
}

// ---------------- Charts ----------------
function renderCharts(flows) {
  // Count by protocol
  const protoCount = {};
  const srcCount = {};
  const dstCount = {};

  flows.forEach(f => {
    protoCount[f.protocol] = (protoCount[f.protocol] || 0) + 1;
    srcCount[f.src_ip] = (srcCount[f.src_ip] || 0) + 1;
    dstCount[f.dest_ip] = (dstCount[f.dest_ip] || 0) + 1;
  });

  drawPieChart('protocolChart', protoCount, 'Traffic by Protocol');
  drawBarChart('srcChart', srcCount, 'Top Source IPs', 10);
  drawBarChart('dstChart', dstCount, 'Top Destination IPs', 10);
}

function drawPieChart(canvasId, dataObj, title) {
  const ctx = document.getElementById(canvasId).getContext('2d');
  new Chart(ctx, {
    type: 'pie',
    data: {
      labels: Object.keys(dataObj),
      datasets: [{
        data: Object.values(dataObj),
        backgroundColor: ['#36A2EB', '#FF6384', '#FFCE56', '#4BC0C0']
      }]
    },
    options: { responsive: true, plugins: { title: { display: true, text: title } } }
  });
}

function drawBarChart(canvasId, dataObj, title, limit = 10) {
  const sorted = Object.entries(dataObj).sort((a, b) => b[1] - a[1]).slice(0, limit);
  const ctx = document.getElementById(canvasId).getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: sorted.map(([k]) => k),
      datasets: [{
        label: 'Count',
        data: sorted.map(([_, v]) => v),
        backgroundColor: '#36A2EB'
      }]
    },
    options: { responsive: true, plugins: { title: { display: true, text: title } } }
  });
}

// ---------------- API Calls ----------------
async function postJSON(path, body) {
  const base = apiBase();
  const r = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return r.json();
}

document.getElementById('refreshBtn').onclick = loadData;
setInterval(() => {
  if (document.getElementById('autoRefresh').checked) loadData();
}, 5000);

document.getElementById('blockBtn').onclick = async () => {
  const ip = document.getElementById('ipInput').value.trim();
  if (!ip) return;
  const res = await postJSON('/api/block', { ip });
  document.getElementById('actionMsg').textContent = res.ok ? `Blocked: ${res.message}` : `Error: ${res.error || res.message}`;
  loadData();
};

async function unblock(ip) {
  const res = await postJSON('/api/unblock', { ip });
  document.getElementById('actionMsg').textContent = res.ok ? `Unblocked: ${res.message}` : `Error: ${res.error || res.message}`;
  loadData();
}
document.getElementById('unblockBtn').onclick = async () => {
  const ip = document.getElementById('ipInput').value.trim();
  if (!ip) return;
  await unblock(ip);
};

// ---------------- Init ----------------
loadData();
