const form = document.getElementById("scanForm");
const btn = document.getElementById("scanBtn");
const btnLabel = document.getElementById("btnLabel");
const radar = document.getElementById("radar");
const resultsBody = document.getElementById("resultsBody");
const formError = document.getElementById("formError");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  formError.textContent = "";

  const target = document.getElementById("target").value.trim();
  const profile = document.getElementById("profile").value;
  const confirmAuthorized = document.getElementById("confirmAuthorized").checked;

  setLoading(true);

  try {
    const res = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, profile, confirmAuthorized }),
    });

    const data = await res.json();

    if (!res.ok) {
      formError.textContent = data.error || "Scan failed.";
      resultsBody.innerHTML = `<p class="placeholder">// no results</p>`;
      return;
    }

    renderResults(data);
  } catch (err) {
    formError.textContent = "Could not reach the server. Is it running?";
  } finally {
    setLoading(false);
  }
});

function setLoading(isLoading) {
  btn.disabled = isLoading;
  btnLabel.textContent = isLoading ? "Scanning..." : "Run Scan";
  radar.classList.toggle("hidden", !isLoading);
  if (isLoading) {
    resultsBody.innerHTML = `<p class="placeholder">// scanning target, please wait...</p>`;
  }
}

function renderResults(data) {
  if (!data.hosts || data.hosts.length === 0) {
    resultsBody.innerHTML = `<p class="placeholder">// no hosts found (target may be down or blocking probes)</p>`;
    return;
  }

  let html = "";

  data.hosts.forEach((host) => {
    const openPorts = host.ports
  ? host.ports.filter((p) => p.state === "open").length
  : 0;

html += `
<div class="scan-summary">
    <h3>📊 Scan Summary</h3>

    <p><strong>Target:</strong> ${escapeHtml(host.address)}</p>

    <p><strong>Hostname:</strong> ${
      host.hostname
        ? escapeHtml(host.hostname)
        : "Unknown"
    }</p>

    <p><strong>Status:</strong> ${escapeHtml(host.status.toUpperCase())}</p>

    <p><strong>Open Ports:</strong> ${openPorts}</p>
</div>
`;
    const statusClass = host.status === "up" ? "up" : "down";
    html += `<div class="host-block">`;
    html += `<div class="host-title">${escapeHtml(host.address)}${host.hostname ? " (" + escapeHtml(host.hostname) + ")" : ""}`;
    html += `<span class="host-status ${statusClass}">${escapeHtml(host.status)}</span></div>`;

    if (host.ports && host.ports.length > 0) {
      html += `<table><thead><tr>
        <th>Port</th>
<th>Protocol</th>
<th>State</th>
<th>Service</th>
<th>Version</th>
<th>Risk</th>
      </tr></thead><tbody>`;

      host.ports.forEach((p) => {
        const stateClass =
          p.state === "open" ? "state-open" : p.state === "filtered" ? "state-filtered" : "state-closed";
        html += `<tr>
          <td>${escapeHtml(p.port)}</td>
          <td>${escapeHtml(p.protocol)}</td>
          <td class="${stateClass}">${escapeHtml(p.state)}</td>
          <td>${escapeHtml(p.service)}</td>
          <td>${escapeHtml((p.product + " " + p.version).trim())}</td>
          <td>${getRisk(p.port)}</td>
        </tr>`;
      });

      html += `</tbody></table>`;
    } else {
      html += `<p class="placeholder">// no port data for this scan type</p>`;
    }
    const recommendations = host.ports
  ? host.ports
      .map((p) => getRecommendation(p.port))
      .filter((r) => r !== "")
  : [];

if (recommendations.length > 0) {

    html += `
    <div class="recommendation-box">

        <h3>🛡 Security Recommendations</h3>

        <ul>
    `;

    recommendations.forEach((r) => {
        html += `<li>${escapeHtml(r)}</li>`;
    });

    html += `
        </ul>
    </div>
    `;
}
    const overallRisk = getOverallRisk(host);

html += `
<div class="recommendation-box">

<h3>🚨 Overall Risk</h3>

<p style="font-size:24px;font-weight:bold;">
${overallRisk.level}
</p>

<p>${overallRisk.reason}</p>

</div>
`;
    html += `</div>`;
  });

  resultsBody.innerHTML = html;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function getRisk(port){

    port = Number(port);

    if(port === 445)
        return "🔴 High";

    if(port === 3389)
        return "🔴 High";

    if(port === 21)
        return "🟠 Medium";

    if(port === 23)
        return "🔴 High";

    if(port === 80)
        return "🟡 Medium";

    if(port === 22)
        return "🟢 Low";

    if(port === 53)
        return "🟢 Low";

    return "🟢 Low";
}
function getRecommendation(port){

    port = Number(port);

    switch(port){

        case 22:
            return "SSH is open. Use key-based authentication and disable root login.";

        case 80:
            return "HTTP is open. Consider using HTTPS to encrypt traffic.";

        case 445:
            return "SMB is open. Restrict access because SMB is a common attack target.";

        case 3389:
            return "RDP is open. Restrict access and enable Network Level Authentication.";

        case 21:
            return "FTP is open. Prefer SFTP or FTPS instead of plain FTP.";

        default:
            return "";
    }

}

function getOverallRisk(host){

    if(!host.ports)
        return {
            level:"🟢 Low",
            reason:"No ports detected."
        };

    const ports = host.ports.map(p => Number(p.port));

    if(ports.includes(445) || ports.includes(3389) || ports.includes(23)){
        return{
            level:"🔴 HIGH",
            reason:"High-risk services were detected. Review SMB, RDP or Telnet exposure."
        };
    }

    if(ports.includes(80) || ports.includes(21)){
        return{
            level:"🟡 MEDIUM",
            reason:"Public-facing services detected. Verify configuration and security."
        };
    }

    return{
        level:"🟢 LOW",
        reason:"Only low-risk services detected."
    };

}
