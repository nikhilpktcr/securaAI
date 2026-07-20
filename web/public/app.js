const loginView = document.getElementById("loginView");
const linkView = document.getElementById("linkView");
const dashboardView = document.getElementById("dashboardView");
const userSlot = document.getElementById("userSlot");
const startFreeBtn = document.getElementById("startFreeBtn");
const linkForm = document.getElementById("linkForm");
const loginStatus = document.getElementById("loginStatus");
const linkStatus = document.getElementById("linkStatus");
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

const SCAN_KEY = "secura_last_scan";
const isVercelHost = /\.vercel\.app$/i.test(window.location.hostname);

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
    userSlot.textContent = "";
  }

  if (!session) {
    showView("login");
    return;
  }

  if (!session.repo) {
    showView("link");
    const help = document.getElementById("linkHelp");
    if (help) {
      help.textContent = isVercelHost
        ? "Free on Vercel: paste a public GitHub repo URL. Secura scans recent JS/TS files."
        : "Paste a public GitHub URL, or a local git path when running npm run web.";
    }
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

async function startFree() {
  loginStatus.textContent = "Starting free session...";
  try {
    await api("/api/start", { method: "POST", body: "{}" });
    const me = await api("/api/me");
    renderSession(me);
    loginStatus.textContent = "";
  } catch (error) {
    // Fallback for older deploys without /api/start
    try {
      await api("/api/login", { method: "POST", body: JSON.stringify({ free: true }) });
      const me = await api("/api/me");
      renderSession(me);
      loginStatus.textContent = "";
    } catch (fallbackError) {
      loginStatus.textContent = fallbackError.message || error.message;
    }
  }
}

async function bootstrap() {
  try {
    const me = await api("/api/me");
    renderSession(me);
  } catch (_err) {
    renderSession(null);
  }
}

startFreeBtn.addEventListener("click", () => {
  void startFree();
});

linkForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  linkStatus.textContent = "Linking repository...";
  try {
    await api("/api/repos/link", {
      method: "POST",
      body: JSON.stringify({ repo: repoInput.value })
    });
    clearCachedScan();
    const me = await api("/api/me");
    renderSession(me);
    linkStatus.textContent = "";
  } catch (error) {
    linkStatus.textContent = error.message;
  }
});

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

relinkBtn.addEventListener("click", () => {
  clearCachedScan();
  showView("link");
});

logoutBtn.addEventListener("click", async () => {
  clearCachedScan();
  await api("/api/logout", { method: "POST", body: "{}" });
  renderSession(null);
});

void bootstrap();
