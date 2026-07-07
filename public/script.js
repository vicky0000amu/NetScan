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
    const statusClass = host.status === "up" ? "up" : "down";
    html += `<div class="host-block">`;
    html += `<div class="host-title">${escapeHtml(host.address)}${host.hostname ? " (" + escapeHtml(host.hostname) + ")" : ""}`;
    html += `<span class="host-status ${statusClass}">${escapeHtml(host.status)}</span></div>`;

    if (host.ports && host.ports.length > 0) {
      html += `<table><thead><tr>
        <th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th>
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
        </tr>`;
      });

      html += `</tbody></table>`;
    } else {
      html += `<p class="placeholder">// no port data for this scan type</p>`;
    }

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
