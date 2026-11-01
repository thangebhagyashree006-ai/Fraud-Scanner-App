let scanType = "url";
let authMode = "login";

const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, ch => ({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
}[ch]));

function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.classList.add("show");
  setTimeout(() => node.classList.remove("show"), 2800);
}
async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed. Please try again.");
  return data;
}
function setScanType(type) {
  scanType = type;
  document.querySelectorAll(".tabs .tab[data-type]").forEach(btn =>
    btn.classList.toggle("active", btn.dataset.type === type));
  $("contentLabel").textContent = type === "url" ? "Website URL" : type === "email" ? "Email content" : "Message content";
  $("scanContent").placeholder = type === "url"
    ? "Paste a suspicious URL, for example https://example.com"
    : type === "email" ? "Paste the email subject and message body here..."
    : "Paste the suspicious SMS, chat or message here...";
  $("senderWrap").classList.toggle("hidden", type !== "email");
}
document.querySelectorAll("[data-type]").forEach(btn => btn.addEventListener("click", () => setScanType(btn.dataset.type)));

$("scanBtn").addEventListener("click", async () => {
  const content = $("scanContent").value.trim();
  if (!content) return toast("Please enter content to scan.");
  const button = $("scanBtn");
  button.disabled = true; button.textContent = "Analyzing…";
  try {
    const result = await api("/api/scan", {method:"POST", body:JSON.stringify({
      type:scanType, content, sender:$("senderEmail").value.trim()
    })});
    renderResult(result);
    await Promise.all([loadHistory(), loadStats()]);
    toast("Scan completed.");
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.innerHTML = 'Analyze now <span>→</span>'; }
});

function renderResult(result) {
  const level = String(result.risk_level || "low").toLowerCase();
  const details = (result.details || []).map(item => `<li>${escapeHtml(item)}</li>`).join("");
  const tips = (result.recommendations || []).map(item => `<li>${escapeHtml(item)}</li>`).join("");
  $("resultPanel").innerHTML = `<div class="result-content">
    <div class="result-top"><div><span class="eyebrow">ANALYSIS COMPLETE</span><h3>Scan result #${escapeHtml(result.scan_id)}</h3></div>
    <div class="score">${Number(result.fraud_score)}<small> / 100</small></div></div>
    <span class="risk-pill risk-${escapeHtml(level)}">${escapeHtml(level)} risk</span>
    <div class="progress"><span style="width:${Math.max(0,Math.min(100,Number(result.fraud_score)))}%"></span></div>
    <h4>Detected indicators</h4><ul>${details || "<li>No details provided.</li>"}</ul>
    <h4>Recommendations</h4><ul>${tips}</ul>
  </div>`;
}

async function loadHistory() {
  try {
    const rows = await api("/api/history");
    $("historyBody").innerHTML = rows.length ? rows.map(row => `<tr>
      <td title="${escapeHtml(row.content)}">${escapeHtml(String(row.content).slice(0,48))}${String(row.content).length>48?"…":""}</td>
      <td>${escapeHtml(row.scan_type)}</td><td>${Number(row.fraud_score)} / 100</td>
      <td><span class="risk-pill risk-${escapeHtml(row.risk_level)}">${escapeHtml(row.risk_level)}</span></td>
      <td>${escapeHtml(new Date(row.timestamp).toLocaleString())}</td></tr>`).join("")
      : '<tr><td colspan="5" class="muted-cell">No scans yet. Run your first scan above.</td></tr>';
  } catch (error) { $("historyBody").innerHTML = `<tr><td colspan="5">${escapeHtml(error.message)}</td></tr>`; }
}
async function loadStats() {
  try {
    const data = await api("/api/stats");
    $("totalScans").textContent = data.total_scans ?? 0;
    $("highRisk").textContent = data.high_risk_scans ?? 0;
    $("totalReports").textContent = data.total_reports ?? 0;
  } catch (_) {}
}
async function loadAlerts() {
  try {
    const alerts = await api("/api/alerts");
    $("alertsGrid").innerHTML = alerts.map(item => `<article class="panel alert-card">
      <span class="eyebrow">SAMPLE ALERT</span><strong>${escapeHtml(item.type)}</strong>
      <div class="alert-count">${escapeHtml(item.count)}</div>
      <p>${escapeHtml(item.location)} · Example reports</p></article>`).join("");
  } catch (error) { $("alertsGrid").textContent = error.message; }
}

$("reportForm").addEventListener("submit", async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  payload.anonymous = form.has("anonymous");
  payload.amount_lost = Number(payload.amount_lost || 0);
  try {
    const result = await api("/api/report", {method:"POST", body:JSON.stringify(payload)});
    $("reportMessage").textContent = `${result.message} (Report #${result.report_id})`;
    event.currentTarget.reset();
    await loadStats();
    toast("Report submitted.");
  } catch (error) { $("reportMessage").textContent = error.message; }
});

function setAuthMode(mode) {
  authMode = mode;
  $("authTitle").textContent = mode === "login" ? "Login" : "Create account";
  $("authSubmit").textContent = mode === "login" ? "Login" : "Register";
  $("emailField").classList.toggle("hidden", mode !== "register");
  $("emailField").querySelector("input").required = mode === "register";
  document.querySelectorAll("[data-auth]").forEach(btn => btn.classList.toggle("active", btn.dataset.auth === mode));
}
$("authToggle").addEventListener("click", () => $("authModal").classList.remove("hidden"));
$("closeModal").addEventListener("click", () => $("authModal").classList.add("hidden"));
$("authModal").addEventListener("click", event => { if (event.target === $("authModal")) $("authModal").classList.add("hidden"); });
document.querySelectorAll("[data-auth]").forEach(btn => btn.addEventListener("click", () => setAuthMode(btn.dataset.auth)));
$("authForm").addEventListener("submit", async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  try {
    const result = await api(authMode === "login" ? "/api/login" : "/api/register",
      {method:"POST", body:JSON.stringify(payload)});
    $("authMessage").textContent = result.message;
    $("authToggle").textContent = `Hi, ${payload.username}`;
    toast(result.message);
    setTimeout(() => $("authModal").classList.add("hidden"), 700);
  } catch (error) { $("authMessage").textContent = error.message; }
});

$("year").textContent = new Date().getFullYear();
setScanType("url");
loadStats(); loadHistory(); loadAlerts();
