const loginView = document.getElementById("loginView");
const linkView = document.getElementById("linkView");
const dashboardView = document.getElementById("dashboardView");
const userSlot = document.getElementById("userSlot");
const linkForm = document.getElementById("linkForm");
const linkFormAlt = document.getElementById("linkFormAlt");
const loginStatus = document.getElementById("loginStatus");
const linkStatus = document.getElementById("linkStatus");
const linkStatusAlt = document.getElementById("linkStatusAlt");
const scanStatus = document.getElementById("scanStatus");
const repoLabel = document.getElementById("repoLabel");
const findingsList = document.getElementById("findingsList");
const statOpen = document.getElementById("statOpen");
const statFiles = document.getElementById("statFiles");
const statScore = document.getElementById("statScore");
const scanBtn = document.getElementById("scanBtn");
const relinkBtn = document.getElementById("relinkBtn");
const logoutBtn = document.getElementById("logoutBtn");
const repoInput = document.getElementById("repoInput");
const repoInputAlt = document.getElementById("repoInputAlt");

const SCAN_KEY = "secura_last_scan";
let latestFindings = [];

async function api(path, options = {}) {
  const resp = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    credentials: "same-origin",
    ...options
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function getCachedScan() {
  try {
    return JSON.parse(sessionStorage.getItem(SCAN_KEY) || "null");
  } catch (_err) {
    return null;
  }
}

function setCachedScan(scan) {
  sessionStorage.setItem(SCAN_KEY, JSON.stringify(scan));
}

function clearCachedScan() {
  sessionStorage.removeItem(SCAN_KEY);
}

function showView(name) {
  loginView.classList.toggle("hidden", name !== "login");
  linkView.classList.toggle("hidden", name !== "link");
  dashboardView.classList.toggle("hidden", name !== "dashboard");
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderTriagePanel(result) {
  const card = result.triage;
  const modeLabel =
    result.mode === "ai-fluency-llm"
      ? "LLM enriched"
      : result.mode === "ai-fluency-local-fallback"
        ? "Local fallback"
        : "Grounded local";

  const actions = (card.next_actions || [])
    .map((action, index) => `<li><span class="triage-step">${index + 1}</span>${escapeHtml(action)}</li>`)
    .join("");
  const context = (card.context_used || [])
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");

  return `
    <div class="triage-card">
      <div class="triage-top">
        <strong>AI triage</strong>
        <span class="chip">${escapeHtml(modeLabel)}</span>
        <span class="chip">confidence ${escapeHtml(String(card.confidence))}</span>
        <span class="chip">fluency ${escapeHtml(String(card.fluency_score))}</span>
      </div>
      <p class="triage-summary">${escapeHtml(card.summary)}</p>
      <p><span class="muted">Intent</span><br />${escapeHtml(card.intent)}</p>
      <p><span class="muted">Reasoning</span><br />${escapeHtml(card.reasoning)}</p>
      <p><span class="muted">MITRE</span><br /><span class="code">${escapeHtml(card.mitre_tactic)}</span></p>
      <p><span class="muted">Impact</span><br />${escapeHtml(card.impact)}</p>
      <div class="triage-columns">
        <div>
          <p class="muted" style="margin-bottom:6px">Next actions</p>
          <ol class="triage-actions">${actions}</ol>
        </div>
        <div>
          <p class="muted" style="margin-bottom:6px">Context used</p>
          <ul class="triage-context">${context}</ul>
        </div>
      </div>
    </div>`;
}

function bindTriageButtons() {
  findingsList.querySelectorAll("[data-triage-index]").forEach((button) => {
    button.addEventListener("click", async () => {
      const index = Number(button.getAttribute("data-triage-index"));
      const finding = latestFindings[index];
      const panel = findingsList.querySelector(`[data-triage-panel="${index}"]`);
      if (!finding || !panel) return;

      if (!panel.classList.contains("hidden") && panel.dataset.loaded === "1") {
        panel.classList.add("hidden");
        button.textContent = "AI triage";
        return;
      }

      button.disabled = true;
      button.textContent = "Triaging…";
      panel.classList.remove("hidden");
      panel.innerHTML = `<div class="triage-card muted">Building grounded triage…</div>`;

      try {
        const result = await api("/api/triage", {
          method: "POST",
          body: JSON.stringify({ finding })
        });
        panel.innerHTML = renderTriagePanel(result);
        panel.dataset.loaded = "1";
        button.textContent = "Hide triage";
      } catch (error) {
        panel.innerHTML = `<div class="triage-card status">${escapeHtml(error.message)}</div>`;
        button.textContent = "Retry triage";
      } finally {
        button.disabled = false;
      }
    });
  });
}

function renderFindings(scan) {
  if (!scan) {
    latestFindings = [];
    findingsList.innerHTML = `<div class="empty">No scan yet. Click <strong>Scan repository</strong>.</div>`;
    statOpen.textContent = "0";
    statFiles.textContent = "0";
    statScore.textContent = "100";
    return;
  }

  latestFindings = Array.isArray(scan.findings) ? scan.findings : [];
  statOpen.textContent = String(scan.stats.open);
  statFiles.textContent = String(scan.stats.scanned);
  statScore.textContent = String(scan.stats.score);

  if (!latestFindings.length) {
    findingsList.innerHTML = `<div class="empty">No security issues found in scanned source/config files.</div>`;
    return;
  }

  findingsList.innerHTML = latestFindings
    .map(
      (item, index) => `
      <article class="finding">
        <h3>${escapeHtml(item.message)}</h3>
        <div class="meta">
          <span class="chip ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>
          <span class="chip">${escapeHtml(item.secretType)}</span>
        </div>
        <p class="code">${escapeHtml(item.filePath)}:${item.line}:${item.character}</p>
        <p class="muted">${escapeHtml(item.explanation)}</p>
        <div class="finding-actions">
          <button type="button" class="secondary" data-triage-index="${index}">AI triage</button>
        </div>
        <div class="triage-panel hidden" data-triage-panel="${index}"></div>
      </article>`
    )
    .join("");

  bindTriageButtons();
}

function renderSession(session) {
  if (session?.user) {
    const free = /guest@secura\.ai/i.test(session.user.email);
    userSlot.textContent = free ? "Free access" : `${session.user.name} · ${session.user.email}`;
  } else {
    userSlot.textContent = "Free access";
  }

  // Always keep the hero explanation visible until a repo is linked.
  if (!session?.repo) {
    showView("login");
    return;
  }

  showView("dashboard");
  repoLabel.textContent = `Linked (${session.repo.source}): ${session.repo.input}`;
  const scan = session.lastScan || getCachedScan();
  renderFindings(scan);
  if (!scan) {
    scanStatus.textContent = "Repository linked. Ready to scan.";
  } else {
    scanStatus.textContent = `Last scan: ${new Date(scan.scannedAt).toLocaleString()}`;
  }
}

async function ensureFreeSession() {
  try {
    await api("/api/start", { method: "POST", body: "{}" });
  } catch (_err) {
    await api("/api/login", { method: "POST", body: JSON.stringify({ free: true }) });
  }
}

async function linkAndScan(repoUrl, statusEl) {
  statusEl.textContent = "Starting free scan...";
  await ensureFreeSession();
  await api("/api/repos/link", {
    method: "POST",
    body: JSON.stringify({ repo: repoUrl })
  });
  clearCachedScan();
  statusEl.textContent = "Scanning repository...";
  const result = await api("/api/scan", { method: "POST", body: "{}" });
  setCachedScan(result.scan);
  const me = await api("/api/me");
  renderSession(me);
  renderFindings(result.scan);
  scanStatus.textContent = `Scan complete · ${result.scan.stats.open} open issue(s) · ${result.scan.stats.scanned} files`;
  statusEl.textContent = "";
}

async function bootstrap() {
  try {
    const me = await api("/api/me");
    renderSession(me);
  } catch (_err) {
    renderSession(null);
  }
}

linkForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = linkForm.querySelector("button[type='submit']");
  if (button) button.disabled = true;
  try {
    await linkAndScan(repoInput.value.trim(), linkStatus);
  } catch (error) {
    linkStatus.textContent = error.message;
  } finally {
    if (button) button.disabled = false;
  }
});

if (linkFormAlt) {
  linkFormAlt.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await linkAndScan(repoInputAlt.value.trim(), linkStatusAlt);
    } catch (error) {
      linkStatusAlt.textContent = error.message;
    }
  });
}

scanBtn.addEventListener("click", async () => {
  scanBtn.disabled = true;
  scanStatus.textContent = "Scanning repository...";
  try {
    const result = await api("/api/scan", { method: "POST", body: "{}" });
    setCachedScan(result.scan);
    renderFindings(result.scan);
    scanStatus.textContent = `Scan complete · ${result.scan.stats.open} open issue(s) · ${result.scan.stats.scanned} files`;
  } catch (error) {
    scanStatus.textContent = error.message;
  } finally {
    scanBtn.disabled = false;
  }
});

relinkBtn.addEventListener("click", async () => {
  clearCachedScan();
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
  } catch (_err) {
    // Ignore logout failures; hero still works.
  }
  if (repoInput) repoInput.value = "";
  renderSession(null);
});

logoutBtn.addEventListener("click", async () => {
  clearCachedScan();
  await api("/api/logout", { method: "POST", body: "{}" });
  renderSession(null);
});

void bootstrap();
