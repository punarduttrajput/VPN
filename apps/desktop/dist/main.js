// Desktop shell frontend. Talks to the Rust backend (which drives
// `ferrum_client_core::FerrumClient`) via Tauri commands + a "client-event" stream.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

// ---- First-run identity setup (GUI PRD FR1) --------------------------------

const setupScreen = $("setup-screen");
const appScreen = $("app-screen");
const setupName = $("setup-name");
const setupCoordinator = $("setup-coordinator");
const setupEndpoint = $("setup-endpoint");
const setupGenerateBtn = $("setup-generate");
const setupImportToggleBtn = $("setup-import-toggle");
const setupImportField = $("setup-import-field");
const setupPrivateKey = $("setup-private-key");
const setupGeneratedField = $("setup-generated-field");
const setupPublicKey = $("setup-public-key");
const setupSaveBtn = $("setup-save");
const setupError = $("setup-error");
const profileNameEl = $("profile-name");
const changeIdentityBtn = $("change-identity");

// The identity actually used to connect — populated from a saved profile (or
// the setup form) and kept only in memory; never re-rendered once set.
let identity = null;

function setupErrorMsg(message) {
  setupError.textContent = message;
  setupError.classList.toggle("hidden", !message);
}

function syncSetupSaveEnabled() {
  const hasKey = Boolean(setupPublicKey.value) || Boolean(setupPrivateKey.value.trim());
  setupSaveBtn.disabled = !hasKey;
}

setupGenerateBtn.addEventListener("click", async () => {
  try {
    const [privateKey, publicKey] = await invoke("generate_identity");
    setupPrivateKey.value = privateKey;
    setupPublicKey.value = publicKey;
    setupGeneratedField.classList.remove("hidden");
    setupImportField.classList.add("hidden");
    setupErrorMsg("");
    syncSetupSaveEnabled();
  } catch (e) {
    setupErrorMsg(`could not generate a key: ${e}`);
  }
});

setupImportToggleBtn.addEventListener("click", () => {
  setupImportField.classList.remove("hidden");
  setupGeneratedField.classList.add("hidden");
  setupPublicKey.value = "";
  syncSetupSaveEnabled();
});

setupPrivateKey.addEventListener("input", syncSetupSaveEnabled);

setupSaveBtn.addEventListener("click", async () => {
  const profile = {
    private_key: setupPrivateKey.value.trim(),
    name: setupName.value.trim() || "desktop",
    endpoint: setupEndpoint.value.trim(),
    coordinator: setupCoordinator.value.trim(),
  };
  if (!profile.private_key) {
    setupErrorMsg("generate or import a private key first");
    return;
  }
  if (!profile.coordinator || !profile.endpoint) {
    setupErrorMsg("coordinator and advertised endpoint are required");
    return;
  }
  try {
    await invoke("save_identity", { profile });
    identity = profile;
    showAppScreen();
  } catch (e) {
    setupErrorMsg(`could not save identity: ${e}`);
  }
});

function showSetupScreen() {
  setupScreen.classList.remove("hidden");
  appScreen.classList.add("hidden");
}

function showAppScreen() {
  profileNameEl.textContent = `${identity.name} · ${identity.coordinator}`;
  setupScreen.classList.add("hidden");
  appScreen.classList.remove("hidden");
}

changeIdentityBtn.addEventListener("click", async () => {
  await invoke("clear_identity");
  identity = null;
  setupPrivateKey.value = "";
  setupPublicKey.value = "";
  setupGeneratedField.classList.add("hidden");
  setupImportField.classList.add("hidden");
  setupErrorMsg("");
  syncSetupSaveEnabled();
  showSetupScreen();
});

// ---- Connect screen ---------------------------------------------------------

const stateEl = $("state");
const peersEl = $("peers");
const peerCountEl = $("peer-count");
const logEl = $("log");
const connectBtn = $("connect");
const disconnectBtn = $("disconnect");
const killSwitchEl = $("kill_switch");
const killSwitchStateEl = $("kill-switch-state");
const transportModeEl = $("transport_mode");
const serverNameField = $("server_name_field");
const masqueProxyField = $("masque_proxy_field");
const privilegeNoteEl = $("privilege-note");

// Show the TLS server-name field for QUIC/MASQUE and the proxy field for MASQUE.
function syncTransportFields() {
  const mode = transportModeEl.value;
  serverNameField.classList.toggle("hidden", mode === "udp");
  masqueProxyField.classList.toggle("hidden", mode !== "masque");
}
transportModeEl.addEventListener("change", syncTransportFields);

function setKillSwitchState(blocked) {
  killSwitchStateEl.textContent = blocked ? "blocking" : (killSwitchEl.checked ? "armed" : "off");
  killSwitchStateEl.className = "badge" + (blocked ? " err" : "");
}

const STATES = ["disconnected", "connecting", "connected", "reconnecting", "failed"];

function setState(name) {
  const key = String(name).toLowerCase();
  stateEl.textContent = name;
  stateEl.className = "state " + (STATES.includes(key) ? key : "disconnected");
  const connected = key === "connected";
  const busy = key === "connecting" || key === "reconnecting";
  connectBtn.disabled = connected || busy;
  disconnectBtn.disabled = key === "disconnected" || key === "failed";
}

function log(message, isErr = false) {
  const li = document.createElement("li");
  const ts = new Date().toLocaleTimeString();
  li.innerHTML = `<span class="ts">${ts}</span><span class="${isErr ? "err" : ""}">${message}</span>`;
  logEl.prepend(li);
  while (logEl.children.length > 50) logEl.lastChild.remove();
}

async function refreshPeers() {
  const peers = await invoke("get_peers");
  peerCountEl.textContent = peers.length;
  peersEl.innerHTML = "";
  if (peers.length === 0) {
    peersEl.innerHTML = '<li class="empty">No peers</li>';
    return;
  }
  for (const p of peers) {
    const li = document.createElement("li");
    const direct = /direct/i.test(p.path);
    li.innerHTML =
      `<span class="path-dot ${direct ? "direct" : "relay"}" title="${p.path}"></span>` +
      `<span class="path">${p.path}</span>` +
      `<div class="key">${p.public_key}</div>` +
      `<div class="endpoint">${p.endpoint} &middot; ${p.allowed_ips.join(", ")}</div>`;
    peersEl.appendChild(li);
  }
}

connectBtn.addEventListener("click", async () => {
  try {
    setState("Connecting");
    await invoke("connect", {
      coordinator: identity.coordinator,
      identity: {
        private_key: identity.private_key,
        name: identity.name,
        endpoint: identity.endpoint,
        tags: [],
      },
      listenPort: Number($("listen_port").value),
      transport: {
        mode: transportModeEl.value,
        server_name: $("server_name").value.trim() || null,
        masque_proxy: $("masque_proxy").value.trim() || null,
        stun_server: $("stun_server").value.trim() || null,
        relay: $("relay").value.trim() || null,
      },
    });
  } catch (e) {
    log(`connect failed: ${e}`, true);
    setState("Failed");
  }
});

disconnectBtn.addEventListener("click", async () => {
  await invoke("disconnect");
});

killSwitchEl.addEventListener("change", async () => {
  await invoke("set_kill_switch", { enabled: killSwitchEl.checked });
  setKillSwitchState(false);
  log(`kill-switch ${killSwitchEl.checked ? "armed" : "disarmed"}`);
});

// Live events from the core: state changes, peer updates, errors.
listen("client-event", (event) => {
  const e = event.payload;
  if (e.kind === "state") {
    setState(e.state);
    log(`state → ${e.state}`);
  } else if (e.kind === "peers") {
    log(`peers updated: ${e.peers}`);
    refreshPeers();
  } else if (e.kind === "error") {
    log(e.message, true);
  } else if (e.kind === "kill-switch") {
    setKillSwitchState(e.blocked);
    log(e.blocked ? "kill-switch: blocking non-tunnel traffic" : "kill-switch: traffic allowed");
  }
});

// The privileged-helper daemon/service is best-effort and its actual status
// isn't yet surfaced as a distinct event (GUI PRD FR4 tracks wiring that up);
// this static note at least tells the user the app doesn't assume elevation.
const PLATFORM_PRIVILEGE_HINT =
  "Opening the tunnel and enforcing the kill-switch use the ferrum-helper " +
  "daemon/service if it's installed, otherwise this app needs to run elevated.";

// Initial paint: load the saved identity (if any) and, once in the app
// screen, the current backend state.
(async () => {
  const saved = await invoke("load_identity");
  if (!saved) {
    showSetupScreen();
    return;
  }
  identity = saved;
  showAppScreen();
  privilegeNoteEl.textContent = PLATFORM_PRIVILEGE_HINT;
  setState(await invoke("get_status"));
  killSwitchEl.checked = await invoke("kill_switch_enabled");
  setKillSwitchState(false);
  syncTransportFields();
  refreshPeers();
})();
