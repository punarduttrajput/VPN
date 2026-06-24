// Desktop shell frontend. Talks to the Rust backend (which drives
// `ferrum_client_core::FerrumClient`) via Tauri commands + a "client-event" stream.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
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
    li.innerHTML =
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
      coordinator: $("coordinator").value.trim(),
      identity: {
        private_key: $("private_key").value.trim(),
        name: $("name").value.trim(),
        endpoint: $("endpoint").value.trim(),
        tags: [],
      },
      listenPort: Number($("listen_port").value),
      transport: {
        mode: transportModeEl.value,
        server_name: $("server_name").value.trim() || null,
        masque_proxy: $("masque_proxy").value.trim() || null,
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

// Initial paint from current backend state.
(async () => {
  setState(await invoke("get_status"));
  killSwitchEl.checked = await invoke("kill_switch_enabled");
  setKillSwitchState(false);
  syncTransportFields();
  refreshPeers();
})();
