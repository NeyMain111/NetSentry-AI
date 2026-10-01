const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const palette = {
  TLS: '#22d3b6', DNS: '#4f8cff', TCP: '#9b7bff', UDP: '#ffb648',
  HTTP: '#55c2ff', HTTPS: '#22d3b6', ICMP: '#ff5d73', ARP: '#f58fe4',
  SSH: '#87d37c', FTP: '#ff9b66', TELNET: '#ff5d73', IPv6: '#6db1ff', OTHER: '#60798c'
};
const severityColors = { info: '#6db1ff', low: '#ffb648', medium: '#ff9866', high: '#ff5d73', critical: '#ff3155' };

let snapshot = { stats: { total_packets: 0, total_bytes: 0, total_alerts: 0, protocols: {} }, packets: [], alerts: [], capture: {} };
let selectedProtocol = 'ALL';
let selectedAlertId = null;
let searchDebounce = null;
let rateHistory = Array(60).fill(0);
let lastTotal = 0;
let lastPollAt = performance.now();
let toastTimer = null;
let navUpdateScheduled = false;
let advisorHistory = [];
let advisorBusy = false;

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c]);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let body = null;
  try { body = await response.json(); } catch (_) { body = {}; }
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

function showToast(message, error = false) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.className = `toast show${error ? ' error' : ''}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.className = 'toast'; }, 3500);
}

const navLinks = $$('.nav a[href^="#"]');
const navSections = navLinks
  .map(link => ({ link, section: document.querySelector(link.getAttribute('href')) }))
  .filter(item => item.section);

function setActiveNav(activeLink) {
  navLinks.forEach(link => {
    const active = link === activeLink;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
}

function updateActiveNav() {
  navUpdateScheduled = false;
  const activationLine = Math.min(180, window.innerHeight * .28);
  const activeItem = navSections.find(item => item.link.classList.contains('active'));
  let current = navSections[0];
  let currentTop = Number.NEGATIVE_INFINITY;

  navSections.forEach(item => {
    const top = item.section.getBoundingClientRect().top;
    if (top > activationLine) return;
    if (top > currentTop + 4) {
      current = item;
      currentTop = top;
    } else if (Math.abs(top - currentTop) <= 4 && item === activeItem) {
      current = item;
    }
  });

  if (current) setActiveNav(current.link);
}

function scheduleNavUpdate() {
  if (navUpdateScheduled) return;
  navUpdateScheduled = true;
  requestAnimationFrame(updateActiveNav);
}

function formatNumber(value) { return Number(value || 0).toLocaleString(); }
function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}
function timeOnly(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString([], { hour12: false });
}
function address(ip, port) { return `${escapeHtml(ip)}${port != null ? `<em>:${escapeHtml(port)}</em>` : ''}`; }

async function loadInterfaces() {
  try {
    const data = await api('/api/interfaces');
    const select = $('#interface');
    select.innerHTML = '<option value="">All interfaces</option>' + data.interfaces.map(name => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join('');
  } catch (error) { showToast(error.message, true); }
}

async function poll() {
  const params = new URLSearchParams({ limit: '300' });
  if (selectedProtocol !== 'ALL') params.set('protocol', selectedProtocol);
  if ($('#suspicious-only').checked) params.set('suspicious', 'true');
  const query = $('#packet-search').value.trim();
  if (query) params.set('q', query);
  try {
    const next = await api(`/api/snapshot?${params}`);
    const now = performance.now();
    const elapsed = Math.max((now - lastPollAt) / 1000, .1);
    const rate = Math.max(0, Math.round((next.stats.total_packets - lastTotal) / elapsed));
    lastTotal = next.stats.total_packets;
    lastPollAt = now;
    rateHistory.push(rate);
    rateHistory = rateHistory.slice(-60);
    snapshot = next;
    render(rate);
    $('#api-dot').className = 'connection-dot online';
    $('#api-label').textContent = 'Engine online';
  } catch (error) {
    $('#api-dot').className = 'connection-dot offline';
    $('#api-label').textContent = 'Engine offline';
  }
}

function render(rate) {
  const { stats, capture } = snapshot;
  $('#total-packets').textContent = formatNumber(stats.total_packets);
  $('#packet-rate').textContent = `${formatNumber(rate)} packets/sec`;
  $('#total-bytes').textContent = formatBytes(stats.total_bytes);
  $('#total-alerts').textContent = formatNumber(stats.total_alerts);
  $('#nav-alert-count').textContent = stats.total_alerts;
  $('#alert-summary').textContent = stats.total_alerts ? 'Review detected indicators' : 'No active findings';
  $('#engine-status').textContent = capture.running ? 'Monitoring' : 'Ready';
  $('#engine-detail').textContent = capture.running ? `${capture.mode === 'demo' ? 'Synthetic demo' : capture.interface || 'Live interfaces'}` : 'Waiting for capture';
  const badge = $('#capture-badge');
  badge.className = `status-badge ${capture.running ? 'live' : 'idle'}`;
  badge.querySelector('span').textContent = capture.running ? `${capture.mode === 'demo' ? 'Demo' : 'Live'} capture active` : 'Capture idle';
  $('#start-btn').disabled = Boolean(capture.running);
  $('#stop-btn').disabled = !capture.running;
  renderProtocols(stats.protocols);
  renderFilters(stats.protocols);
  renderPackets(snapshot.packets);
  renderAlerts(snapshot.alerts);
  drawChart();
}

function renderProtocols(protocols) {
  const entries = Object.entries(protocols).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  $('#protocol-total').textContent = formatNumber(total);
  if (!total) {
    $('#protocol-donut').style.background = 'conic-gradient(#243746 0 100%)';
    $('#protocol-legend').innerHTML = '<p class="empty-state">Start a capture to see protocols.</p>';
    return;
  }
  let position = 0;
  const stops = entries.map(([name, count]) => {
    const start = position;
    position += count / total * 100;
    return `${palette[name] || palette.OTHER} ${start}% ${position}%`;
  });
  $('#protocol-donut').style.background = `conic-gradient(${stops.join(',')})`;
  $('#protocol-legend').innerHTML = entries.slice(0, 6).map(([name, count]) => `
    <div class="protocol-item" style="--item-color:${palette[name] || palette.OTHER}"><i></i><span>${escapeHtml(name)}</span><b>${Math.round(count / total * 100)}%</b></div>
  `).join('');
}

function renderFilters(protocols) {
  const container = $('#protocol-filters');
  const names = Object.keys(protocols).sort((a, b) => protocols[b] - protocols[a]);
  const signature = ['ALL', ...names].join('|');
  if (container.dataset.signature === signature) return;
  container.dataset.signature = signature;
  container.innerHTML = ['ALL', ...names].map(name => `<button class="filter-chip${selectedProtocol === name ? ' active' : ''}" data-protocol="${escapeHtml(name)}">${name === 'ALL' ? 'All' : escapeHtml(name)}</button>`).join('');
}

function renderPackets(packets) {
  const rows = $('#packet-rows');
  $('#packet-count').textContent = `Showing ${packets.length} packet${packets.length === 1 ? '' : 's'}`;
  if (!packets.length) {
    rows.innerHTML = '<tr class="empty-row"><td colspan="7"><div class="empty-illustration">⇄</div><strong>No matching packets</strong><span>Change the filters or start a capture.</span></td></tr>';
    return;
  }
  rows.innerHTML = packets.map(packet => {
    const color = palette[packet.protocol] || palette.OTHER;
    return `<tr class="${packet.suspicious ? 'suspicious' : ''}" data-packet="${packet.id}">
      <td class="time-cell">${timeOnly(packet.captured_at)}</td>
      <td class="address">${address(packet.src, packet.src_port)}</td>
      <td class="address">${address(packet.dst, packet.dst_port)}</td>
      <td><span class="protocol-pill" style="--pill-color:${color}">${escapeHtml(packet.protocol)}</span></td>
      <td>${formatBytes(packet.length)}</td>
      <td class="info-cell" title="${escapeHtml(packet.info)}">${escapeHtml(packet.info)}</td>
      <td class="row-alert">${packet.suspicious ? '△' : '›'}</td>
    </tr>`;
  }).join('');
}

function renderAlerts(alerts) {
  $('#alert-badge').textContent = `${alerts.length} finding${alerts.length === 1 ? '' : 's'}`;
  if (!alerts.length) {
    $('#alert-list').innerHTML = '<div class="large-empty"><div class="shield-check">✓</div><strong>No threats detected</strong><p>Findings from the rule engine will appear here with supporting evidence.</p></div>';
    return;
  }
  $('#alert-list').innerHTML = alerts.map(alert => {
    const color = severityColors[alert.severity] || severityColors.info;
    return `<div class="alert-card" style="--severity:${color}">
      <div class="alert-icon">△</div>
      <div><h3>${escapeHtml(alert.title)}</h3><p>${escapeHtml(alert.description)}</p><div class="alert-meta"><span>${timeOnly(alert.detected_at)}</span><span>${escapeHtml(alert.source)} → ${escapeHtml(alert.destination || '—')}</span></div></div>
      <div class="alert-actions"><span class="severity">${escapeHtml(alert.severity)}</span><button class="ask-alert" data-alert="${alert.id}">Ask AI ✦</button></div>
    </div>`;
  }).join('');
}

function drawChart() {
  const canvas = $('#traffic-chart');
  const rect = canvas.getBoundingClientRect();
  const scale = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.round(rect.width * scale));
  canvas.height = Math.max(1, Math.round(rect.height * scale));
  const ctx = canvas.getContext('2d');
  ctx.scale(scale, scale);
  const width = rect.width, height = rect.height;
  const pad = { top: 14, right: 8, bottom: 24, left: 34 };
  const chartW = width - pad.left - pad.right, chartH = height - pad.top - pad.bottom;
  const max = Math.max(10, ...rateHistory);
  ctx.strokeStyle = 'rgba(151,179,201,.09)';
  ctx.fillStyle = '#546d80';
  ctx.font = '8px system-ui';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + chartH * i / 4;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(width - pad.right, y); ctx.stroke();
    ctx.fillText(String(Math.round(max * (1 - i / 4))), 3, y + 3);
  }
  const points = rateHistory.map((value, i) => [pad.left + chartW * i / (rateHistory.length - 1), pad.top + chartH * (1 - value / max)]);
  const gradient = ctx.createLinearGradient(0, pad.top, 0, height - pad.bottom);
  gradient.addColorStop(0, 'rgba(34,211,182,.25)'); gradient.addColorStop(1, 'rgba(34,211,182,0)');
  ctx.beginPath(); ctx.moveTo(points[0][0], height - pad.bottom); points.forEach(([x,y]) => ctx.lineTo(x,y)); ctx.lineTo(points.at(-1)[0], height - pad.bottom); ctx.closePath(); ctx.fillStyle = gradient; ctx.fill();
  ctx.beginPath(); points.forEach(([x,y], i) => i ? ctx.lineTo(x,y) : ctx.moveTo(x,y)); ctx.strokeStyle = '#22d3b6'; ctx.lineWidth = 2; ctx.stroke();
  ctx.fillStyle = '#546d80'; ctx.fillText('-60s', pad.left, height - 5); ctx.fillText('now', width - pad.right - 18, height - 5);
}

function openPacket(packetId) {
  const packet = snapshot.packets.find(item => item.id === packetId);
  if (!packet) return;
  $('#drawer-title').textContent = `Packet #${packet.id}`;
  const fields = [
    ['Captured', packet.captured_at], ['Protocol', `${packet.protocol} / ${packet.transport}`],
    ['Source', `${packet.src}${packet.src_port != null ? ':' + packet.src_port : ''}`],
    ['Destination', `${packet.dst}${packet.dst_port != null ? ':' + packet.dst_port : ''}`],
    ['Length', formatBytes(packet.length)], ['Direction', packet.direction],
    ['TCP flags', packet.tcp_flags || '—'], ['Suspicious', packet.suspicious ? `Yes (${packet.severity})` : 'No'],
    ['Details', packet.info || '—', true], ['DNS query', packet.dns_query || '—', true]
  ];
  $('#drawer-content').innerHTML = fields.map(([label, value, full]) => `<div class="detail-item${full ? ' full' : ''}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
  $('#packet-drawer').classList.add('open');
  $('#packet-drawer').setAttribute('aria-hidden', 'false');
}

function selectAlert(alertId) {
  const alert = snapshot.alerts.find(item => item.id === alertId);
  if (!alert) return;
  selectedAlertId = alertId;
  const selected = $('#selected-alert');
  selected.classList.remove('hidden');
  selected.innerHTML = `<button type="button" id="clear-selected-alert">×</button>Context: ${escapeHtml(alert.title)} (${escapeHtml(alert.severity)})`;
  $('#advisor-question').value = 'Explain this alert and tell me what to investigate first.';
  $('#advisor').scrollIntoView({ behavior: 'smooth', block: 'center' });
  $('#advisor-question').focus();
}

function setAdvisorStatus(state, label, message) {
  const badge = $('#advisor-provider');
  badge.textContent = label;
  badge.className = `model-badge ${state}`;
  badge.title = message || label;
  $('#advisor-status-note').textContent = message || '';
}

async function loadAdvisorStatus() {
  try {
    const status = await api('/api/advisor/status');
    if (status.state === 'ready') {
      setAdvisorStatus('ready', `${status.model} · local AI`, status.message);
    } else if (status.state === 'model_missing') {
      setAdvisorStatus('warning', 'Model not installed', status.message);
    } else if (status.state === 'unreachable') {
      setAdvisorStatus('offline', 'Ollama offline', status.message);
    } else {
      setAdvisorStatus('warning', 'Rule fallback', status.message);
    }
  } catch (error) {
    setAdvisorStatus('offline', 'AI status unknown', error.message);
  }
}

function appendMessage(text, role, temporary = false) {
  const log = $('#chat-log');
  const message = document.createElement('div');
  message.className = `message ${role}${temporary ? ' thinking' : ''}`;
  if (temporary) message.id = 'thinking-message';
  const icon = document.createElement('span'); icon.textContent = role === 'user' ? '●' : '✦';
  const body = document.createElement('p'); body.textContent = text;
  message.append(icon, body); log.appendChild(message); log.scrollTop = log.scrollHeight;
}

async function askAdvisor(question) {
  if (advisorBusy) return;
  advisorBusy = true;
  const submit = $('#advisor-form button[type="submit"]');
  submit.disabled = true;
  appendMessage(question, 'user');
  appendMessage('Analysing the current metadata…', 'assistant', true);
  try {
    const data = await api('/api/advisor', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, alert_id: selectedAlertId, history: advisorHistory.slice(-12) })
    });
    $('#thinking-message')?.remove();
    appendMessage(data.answer, 'assistant');
    advisorHistory.push(
      { role: 'user', content: question },
      { role: 'assistant', content: data.answer }
    );
    advisorHistory = advisorHistory.slice(-12);
    if (data.provider === 'ollama') {
      setAdvisorStatus('ready', `${data.model} · local AI`, 'The answer was generated by the local language model with conversation memory and current capture context.');
    } else {
      setAdvisorStatus('warning', 'Rule fallback', data.notice || 'The local language model was unavailable, so a limited rule response was used.');
      if (data.notice) showToast(data.notice, true);
    }
  } catch (error) {
    $('#thinking-message')?.remove();
    appendMessage(`I could not answer: ${error.message}`, 'assistant');
  } finally {
    advisorBusy = false;
    submit.disabled = false;
    $('#advisor-question').focus();
  }
}

$('#capture-mode').addEventListener('change', event => $('#interface-wrap').classList.toggle('hidden', event.target.value !== 'live'));
$('#start-btn').addEventListener('click', async () => {
  const mode = $('#capture-mode').value;
  try {
    await api('/api/capture/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode, interface: mode === 'live' ? ($('#interface').value || null) : null }) });
    showToast(`${mode === 'demo' ? 'Demo' : 'Live'} capture started.`); await poll();
  } catch (error) { showToast(error.message, true); }
});
$('#stop-btn').addEventListener('click', async () => {
  try { await api('/api/capture/stop', { method: 'POST' }); showToast('Capture stopped.'); await poll(); }
  catch (error) { showToast(error.message, true); }
});
$('#clear-btn').addEventListener('click', async () => {
  if (!confirm('Clear all captured packet metadata and alerts?')) return;
  try { await api('/api/data', { method: 'DELETE' }); lastTotal = 0; rateHistory = Array(60).fill(0); showToast('Captured metadata cleared.'); await poll(); }
  catch (error) { showToast(error.message, true); }
});
$('#import-btn').addEventListener('click', () => $('#pcap-input').click());
$('#pcap-input').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  const form = new FormData(); form.append('file', file);
  showToast(`Importing ${file.name}…`);
  try { const data = await api('/api/import/pcap', { method: 'POST', body: form }); showToast(`Imported ${formatNumber(data.packets)} packets.`); await poll(); }
  catch (error) { showToast(error.message, true); }
  event.target.value = '';
});
$('#protocol-filters').addEventListener('click', event => {
  const button = event.target.closest('[data-protocol]'); if (!button) return;
  selectedProtocol = button.dataset.protocol; $$('.filter-chip').forEach(item => item.classList.toggle('active', item === button)); poll();
});
$('#suspicious-only').addEventListener('change', poll);
$('#packet-search').addEventListener('input', () => { clearTimeout(searchDebounce); searchDebounce = setTimeout(poll, 300); });
$('#packet-rows').addEventListener('click', event => { const row = event.target.closest('[data-packet]'); if (row) openPacket(Number(row.dataset.packet)); });
$('#alert-list').addEventListener('click', event => { const button = event.target.closest('[data-alert]'); if (button) selectAlert(Number(button.dataset.alert)); });
$('#selected-alert').addEventListener('click', event => { if (event.target.id === 'clear-selected-alert') { selectedAlertId = null; $('#selected-alert').classList.add('hidden'); } });
$('#advisor-form').addEventListener('submit', event => { event.preventDefault(); const input = $('#advisor-question'); const question = input.value.trim(); if (!question) return; input.value = ''; askAdvisor(question); });
$('#advisor-question').addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    $('#advisor-form').requestSubmit();
  }
});
navLinks.forEach(link => link.addEventListener('click', () => setActiveNav(link)));
$$('[data-close-drawer]').forEach(element => element.addEventListener('click', () => { $('#packet-drawer').classList.remove('open'); $('#packet-drawer').setAttribute('aria-hidden', 'true'); }));
window.addEventListener('resize', drawChart);
window.addEventListener('scroll', scheduleNavUpdate, { passive: true });
window.addEventListener('hashchange', scheduleNavUpdate);
document.addEventListener('keydown', event => { if (event.key === 'Escape') $('#packet-drawer').classList.remove('open'); });

loadInterfaces();
$('#interface-wrap').classList.toggle('hidden', $('#capture-mode').value !== 'live');
loadAdvisorStatus();
poll();
scheduleNavUpdate();
setInterval(poll, 1000);
setInterval(loadAdvisorStatus, 30000);
