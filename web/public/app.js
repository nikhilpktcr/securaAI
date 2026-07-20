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

function renderFindings(scan) {
  if (!scan) {
    findingsList.innerHTML = `<div class="empty">No scan yet. Click <strong>Scan repository</strong>.</div>`;
    statOpen.textContent = "0";
    statFiles.textContent = "0";
    statScore.textContent = "100";
    return;
  }

  statOpen.textContent = String(scan.stats.open);
  statFiles.textContent = String(scan.stats.scanned);
  statScore.textContent = String(scan.stats.score);

  if (!scan.findings.length) {
    findingsList.innerHTML = `<div class="empty">No security issues found in scanned JS/TS files.</div>`;
    return;
  }

  findingsList.innerHTML = scan.findings
    .map(
      (item) => `
      <article class="finding">
        <h3>${escapeHtml(item.message)}</h3>
        <div class="meta">
          <span class="chip ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>
          <span class="chip">${escapeHtml(item.secretType)}</span>
        </div>
        <p class="code">${escapeHtml(item.filePath)}:${item.line}:${item.character}</p>
        <p class="muted">${escapeHtml(item.explanation)}</p>
      </article>`
    )
    .join("");
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
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
