const $ = (id) => document.getElementById(id);

function localTime(value) {
  if (!value) return "Not checked";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], { day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}
function showBanner(message, type = "error") {
  const el = $("banner");
  el.textContent = message;
  el.className = `banner ${type}`;
}
function clearBanner() {
  $("banner").className = "banner hidden";
  $("banner").textContent = "";
}
function statusClass(status) {
  const s = String(status || "").toUpperCase();
  if (s === "SAFE" || ["ACTIVE", "REACHABLE", "CONFIGURED", "ENDPOINT FOUND", "PUBLISHED"].includes(s)) return "good";
  if (s === "ALERT" || s === "ERROR" || s.includes("FAILED")) return "bad";
  return "warn";
}
function pillClass(status) {
  const s = String(status || "").toUpperCase();
  if (s === "SAFE" || s === "REACHABLE") return "pill-safe";
  if (s === "ALERT" || s === "ERROR") return "pill-alert";
  return "pill-neutral";
}
async function refreshDashboard(showMessage = false) {
  const response = await fetch("/api/status", { cache: "no-store" });
  const data = await response.json();
  if (!response.ok || !data.ok) throw new Error(data.error || "Could not load dashboard status.");
  $("connection-label").textContent = data.demo_mode ? "Local demo mode" : "Backend connected";
  if (data.demo_mode) {
    showBanner("DEMO MODE: displayed SAFE/ALERT results are simulated. No AWS resources are contacted. For real checks, configure AWS credentials and set DEMO_MODE=false in .env.", "success");
    $("check-button").textContent = "▶ Run Demo Check";
  }
  $("bucket-name").textContent = data.bucket.bucket || "Not configured";
  $("bucket-pill").textContent = data.bucket.status || "Not checked";
  $("bucket-pill").className = `pill ${pillClass(data.bucket.status)}`;
  $("bucket-region").textContent = `Region: ${data.bucket.region || "—"}`;
  $("pab-status").textContent = data.bucket.public_access_block || "Not checked";
  $("mqtt-topic").textContent = data.mqtt.topic || "—";
  $("iot-topic").textContent = data.mqtt.topic || "—";
  $("mqtt-message").textContent = data.mqtt.latest_message || "No message observed";
  $("iot-last-status").textContent = data.mqtt.latest_message || "None";
  $("iot-publish-mode").textContent = data.mqtt.publish_mode || "Unknown";
  $("last-updated").textContent = localTime(data.last_updated);

  const latest = data.latest;
  if (latest) {
    $("overall-status").textContent = latest.status;
    $("overall-status").className = `big-status ${latest.status.toLowerCase()}`;
    $("overall-message").textContent = latest.message || "Status returned by Lambda.";
    $("last-check").textContent = localTime(latest.checked_at);
    $("condition-detail").textContent = latest.condition || "Not included in Lambda response";
    $("result-detail").textContent = latest.message || "No message included in Lambda response.";
    $("lambda-name").textContent = latest.lambda_function || "Not configured";
    $("iot-publish-detail").textContent = latest.iot_publish?.detail || "No publishing result recorded.";
  } else {
    $("overall-status").textContent = "NOT CHECKED";
    $("overall-status").className = "big-status neutral";
    $("overall-message").textContent = "Run a security check to fetch a real result from AWS Lambda.";
    $("last-check").textContent = "Not checked";
    $("condition-detail").textContent = "Not checked";
    $("result-detail").textContent = "No result returned yet.";
    $("lambda-name").textContent = "Not configured";
  }

  const serviceRoot = $("services-list");
  serviceRoot.innerHTML = (data.services || []).map(service => `
    <div class="service-row">
      <div><div class="service-name">${escapeHtml(service.name)}</div>
      <div class="service-detail">${escapeHtml(service.detail || "")}</div></div>
      <span class="service-state ${statusClass(service.status)}">${escapeHtml(service.status)}</span>
    </div>`).join("") || '<p class="muted">No service status available.</p>';

  const alerts = (data.events || []).filter(e => String(e.status).toUpperCase() === "ALERT" || String(e.status).toUpperCase() === "ERROR");
  $("alerts-list").innerHTML = alerts.length ? alerts.slice(0, 8).map(event => `
    <div class="alert-item">
      <div class="alert-icon">!</div>
      <div><div class="alert-title">${escapeHtml(event.event || "Security alert")}</div>
      <div class="muted tiny">${escapeHtml(event.detail || "No details supplied.")}</div>
      <div class="alert-meta">${escapeHtml(localTime(event.time))} · ${escapeHtml(event.source || "Dashboard")}</div></div>
    </div>`).join("") : '<p class="muted">No security alerts detected in the dashboard-observed history.</p>';

  $("events-table").innerHTML = (data.events || []).length ? data.events.slice(0, 30).map(event => `
    <tr><td>${escapeHtml(localTime(event.time))}</td><td>${escapeHtml(event.event)}</td>
    <td><span class="event-pill ${String(event.status).toLowerCase() === "safe" ? "safe" : ["alert","error"].includes(String(event.status).toLowerCase()) ? "alert" : ""}">${escapeHtml(event.status)}</span></td>
    <td>${escapeHtml(event.source)}</td><td>${escapeHtml(event.detail || "")}</td></tr>`).join("") :
    '<tr><td colspan="5" class="muted">No dashboard events recorded yet. Click Run Security Check to start.</td></tr>';
  if (showMessage) showBanner("Dashboard refreshed from the backend. AWS status fields reflect only the checks available to this app.", "success");
}
async function runCheck() {
  const button = $("check-button");
  button.disabled = true;
  button.textContent = "Running check…";
  clearBanner();
  try {
    const response = await fetch("/api/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error(data.error || "Security check failed.");
    await refreshDashboard();
    showBanner(`Lambda returned ${data.latest.status}. ${data.latest.message || ""}`, data.latest.status === "SAFE" ? "success" : "error");
  } catch (error) {
    showBanner(error.message || "Network error while contacting the backend.");
    $("connection-label").textContent = "Check failed";
  } finally {
    button.disabled = false;
    button.textContent = "▶ Run Security Check";
  }
}
$("refresh-button").addEventListener("click", async () => {
  clearBanner();
  try { await refreshDashboard(true); }
  catch (error) { showBanner(error.message || "Could not refresh dashboard."); }
});
$("check-button").addEventListener("click", runCheck);
window.addEventListener("DOMContentLoaded", async () => {
  try { await refreshDashboard(); }
  catch (error) {
    $("connection-label").textContent = "Backend unavailable";
    showBanner(error.message || "Start the Flask backend, then refresh this page.");
  }
});
