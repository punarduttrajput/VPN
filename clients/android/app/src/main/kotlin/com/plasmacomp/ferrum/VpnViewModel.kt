package com.plasmacomp.ferrum

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import uniffi.ferrum_client_core.ConnectionState
import uniffi.ferrum_client_core.PeerStatus

data class VpnUiState(
    val connectionState: ConnectionState = ConnectionState.DISCONNECTED,
    val address: String? = null,
    val peers: List<PeerStatus> = emptyList(),
    val coordinator: String = "",
    val deviceName: String = "",
    val stunServer: String = "",
    val relay: String = "",
    val killSwitch: Boolean = false,
    val vpnPermissionNeeded: Boolean = false,
)

class VpnViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = app.getSharedPreferences("ferrum_prefs", Context.MODE_PRIVATE)

    private val _ui = MutableStateFlow(
        VpnUiState(
            coordinator = prefs.getString("coordinator", "") ?: "",
            deviceName  = prefs.getString("device_name", android.os.Build.MODEL) ?: "",
            stunServer  = prefs.getString("stun_server", "") ?: "",
            relay       = prefs.getString("relay", "") ?: "",
            killSwitch  = prefs.getBoolean("kill_switch", false),
        )
    )
    val ui: StateFlow<VpnUiState> = _ui.asStateFlow()

    init {
        viewModelScope.launch {
            FerrumVpnService.state.collect { s ->
                _ui.update { it.copy(connectionState = s) }
            }
        }
        viewModelScope.launch {
            FerrumVpnService.peers.collect { p ->
                _ui.update { it.copy(peers = p) }
            }
        }
        viewModelScope.launch {
            FerrumVpnService.address.collect { a ->
                _ui.update { it.copy(address = a) }
            }
        }
    }

    fun setCoordinator(v: String)  { _ui.update { it.copy(coordinator = v) }; prefs.edit().putString("coordinator", v).apply() }
    fun setDeviceName(v: String)   { _ui.update { it.copy(deviceName = v) };  prefs.edit().putString("device_name", v).apply() }
    fun setStunServer(v: String)   { _ui.update { it.copy(stunServer = v) };  prefs.edit().putString("stun_server", v).apply() }
    fun setRelay(v: String)        { _ui.update { it.copy(relay = v) };       prefs.edit().putString("relay", v).apply() }
    fun setKillSwitch(v: Boolean)  { _ui.update { it.copy(killSwitch = v) };  prefs.edit().putBoolean("kill_switch", v).apply() }

    /** Returns an intent to request VPN permission if needed, null if already granted. */
    fun prepareVpnIntent(context: Context): Intent? = VpnService.prepare(context)

    fun connect(context: Context) {
        val s = _ui.value
        val intent = Intent(context, FerrumVpnService::class.java).apply {
            action = FerrumVpnService.ACTION_START
            putExtra(FerrumVpnService.EXTRA_COORDINATOR, s.coordinator)
            putExtra(FerrumVpnService.EXTRA_DEVICE_NAME, s.deviceName)
            if (s.stunServer.isNotBlank()) putExtra(FerrumVpnService.EXTRA_STUN_SERVER, s.stunServer)
            if (s.relay.isNotBlank())      putExtra(FerrumVpnService.EXTRA_RELAY, s.relay)
        }
        context.startForegroundService(intent)
    }

    fun disconnect(context: Context) {
        context.startService(
            Intent(context, FerrumVpnService::class.java).apply {
                action = FerrumVpnService.ACTION_STOP
            }
        )
    }
}
