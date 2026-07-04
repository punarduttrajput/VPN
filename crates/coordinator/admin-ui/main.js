// Ferrum coordinator admin panel. Talks to the coordinator's own admin HTTP
// API (same origin — no separate backend). Auth is a bearer JWT the operator
// pastes in; it's kept only in this tab's sessionStorage and sent as
// `Authorization: Bearer <token>` on every request. There is no login flow
// here (no OAuth2 redirect) — the token comes from wherever the operator's
// IdP already issues one, mirroring the CLI's own `--token-file` pattern.
const $ = (id) => document.getElementById(id);

const TOKEN_KEY = "ferrum-admin-token";

const tokenScreen = $("token-screen");
const appScreen = $("app-screen");
const tokenInput = $("token-input");
const tokenConnectBtn = $("token-connect");
const statusBanner = $("status-banner");
const refreshBtn = $("refresh");
const signOutBtn = $("sign-out");
const devicesEl = $("devices");
const policyAllowAll = $("policy-allow-all");
const policyRulesEl = $("policy-rules");
const policyAddRuleBtn = $("policy-add-rule");
const policySaveBtn = $("policy-save");

function banner(message, kind) {
  if (!message) {
    statusBanner.classList.add("hidden");
    statusBanner.textContent = "";
    return;
  }
  statusBanner.textContent = message;
  statusBanner.className = kind === "ok" ? "ok" : "err";
}

function getToken() {
  return sessionStorage.getItem(TOKEN_KEY) || "";
}

function setToken(token) {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

function showApp() {
  tokenScreen.classList.add("hidden");
  appScreen.classList.remove("hidden");
}

function showTokenScreen() {
  appScreen.classList.add("hidden");
  tokenScreen.classList.remove("hidden");
}

// Thin fetch wrapper: attaches the bearer token and treats 401/403 as
// "the token isn't good enough" rather than a generic error, sending the
// operator back to the token screen instead of leaving a broken panel up.
async function api(path, options = {}) {
  const resp = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { "content-type": "application/json" } : {}),
      authorization: `Bearer ${getToken()}`,
      ...options.headers,
    },
  });
  if (resp.status === 401 || resp.status === 403) {
    const text = await resp.text().catch(() => "");
    setToken("");
    showTokenScreen();
    banner(text || "token rejected — sign in again", "err");
    throw new Error(text || `HTTP ${resp.status}`);
  }
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(text || `HTTP ${resp.status}`);
  }
  return resp;
}

function renderDevices(devices) {
  devicesEl.innerHTML = "";
  if (devices.length === 0) {
    devicesEl.innerHTML = '<li class="empty">No devices registered.</li>';
    return;
  }
  for (const d of devices) {
    const li = document.createElement("li");
    const tags = (d.tags || [])
      .map((t) => `<span class="badge">${escapeHtml(t)}</span>`)
      .join("");
    li.innerHTML = `
      <div class="info">
        <span><strong>${escapeHtml(d.name)}</strong> <span class="ip">${escapeHtml(d.tunnel_ip)}</span></span>
        <span class="key">${escapeHtml(d.public_key)}</span>
        <span class="endpoint">${escapeHtml(d.endpoint || "(no endpoint yet)")}</span>
        <span class="tags">${tags}</span>
      </div>
      <button class="link" data-key="${escapeAttr(d.public_key)}">Revoke</button>
    `;
    li.querySelector("button").addEventListener("click", (e) => {
      revokeDevice(e.target.dataset.key, d.name);
    });
    devicesEl.appendChild(li);
  }
}

async function loadDevices() {
  const resp = await api("/api/devices");
  renderDevices(await resp.json());
}

async function revokeDevice(publicKey, name) {
  if (!confirm(`Revoke "${name}"? It will lose access immediately.`)) return;
  try {
    await api("/api/devices/revoke", {
      method: "POST",
      body: JSON.stringify({ public_key: publicKey }),
    });
    banner(`Revoked ${name}.`, "ok");
    await loadDevices();
  } catch (e) {
    banner(`Revoke failed: ${e.message}`, "err");
  }
}

function addRuleRow(rule) {
  const li = document.createElement("li");
  li.className = "rule-row";
  li.innerHTML = `
    <label>src tags (comma-separated, or *)
      <input class="rule-src" value="${escapeAttr((rule?.src || []).join(", "))}" />
    </label>
    <label>dst tags (comma-separated, or *)
      <input class="rule-dst" value="${escapeAttr((rule?.dst || []).join(", "))}" />
    </label>
    <button class="link">Remove</button>
  `;
  li.querySelector("button").addEventListener("click", () => li.remove());
  policyRulesEl.appendChild(li);
}

function renderPolicy(policy) {
  policyAllowAll.checked = Boolean(policy.allow_all);
  policyRulesEl.innerHTML = "";
  for (const rule of policy.rules || []) addRuleRow(rule);
}

async function loadPolicy() {
  const resp = await api("/api/policy");
  renderPolicy(await resp.json());
}

function splitTags(value) {
  return value
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

async function savePolicy() {
  const rules = Array.from(policyRulesEl.querySelectorAll(".rule-row")).map((row) => ({
    src: splitTags(row.querySelector(".rule-src").value),
    dst: splitTags(row.querySelector(".rule-dst").value),
  }));
  const policy = { allow_all: policyAllowAll.checked, rules };
  try {
    await api("/api/policy", { method: "PUT", body: JSON.stringify(policy) });
    banner("Policy saved.", "ok");
    await loadPolicy();
  } catch (e) {
    banner(`Save failed: ${e.message}`, "err");
  }
}

async function loadAll() {
  await Promise.all([loadDevices(), loadPolicy()]);
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s ?? "";
  return div.innerHTML;
}

function escapeAttr(s) {
  return escapeHtml(s).replaceAll('"', "&quot;");
}

tokenConnectBtn.addEventListener("click", async () => {
  const token = tokenInput.value.trim();
  if (!token) return;
  setToken(token);
  try {
    showApp();
    banner("");
    await loadAll();
  } catch (e) {
    // api() already routed us back to the token screen with a banner.
  }
});

refreshBtn.addEventListener("click", () => loadAll().catch(() => {}));
policyAddRuleBtn.addEventListener("click", () => addRuleRow(null));
policySaveBtn.addEventListener("click", () => savePolicy());
signOutBtn.addEventListener("click", () => {
  setToken("");
  banner("");
  showTokenScreen();
});

// If a token from an earlier visit is still in this tab's session, try it
// immediately instead of making the operator paste it again.
if (getToken()) {
  showApp();
  loadAll().catch(() => {});
} else {
  showTokenScreen();
}
