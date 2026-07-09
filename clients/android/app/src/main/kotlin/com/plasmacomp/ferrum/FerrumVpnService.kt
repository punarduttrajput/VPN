package com.plasmacomp.ferrum

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.IBinder
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import uniffi.ferrum_client_core.*

class FerrumVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.plasmacomp.ferrum.START_VPN"
        const val ACTION_STOP  = "com.plasmacomp.ferrum.STOP_VPN"

        const val EXTRA_COORDINATOR = "coordinator"
        const val EXTRA_DEVICE_NAME = "device_name"
        const val EXTRA_STUN_SERVER = "stun_server"
        const val EXTRA_RELAY       = "relay"
        /** Comma-separated DNS resolver IPs — a local override of the
         *  coordinator-advertised list (PRD leak-protection.md). */
        const val EXTRA_DNS         = "dns"
        /** IPv6 policy: "auto" (default) | "block" | "tunnel" | "off". */
        const val EXTRA_IPV6_POLICY = "ipv6_policy"

        private const val NOTIF_CHANNEL = "ferrum_vpn"
        private const val NOTIF_ID = 1

        private val _state   = MutableStateFlow<ConnectionState>(ConnectionState.DISCONNECTED)
        private val _peers   = MutableStateFlow<List<PeerStatus>>(emptyList())
        private val _address = MutableStateFlow<String?>(null)

        val state:   StateFlow<ConnectionState> = _state.asStateFlow()
        val peers:   StateFlow<List<PeerStatus>> = _peers.asStateFlow()
        val address: StateFlow<String?>          = _address.asStateFlow()
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var client: FfiFerrumClient? = null
    private var tun: ParcelFileDescriptor? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startTunnel(intent)
            ACTION_STOP  -> stopTunnel()
        }
        return START_STICKY
    }

    private fun startTunnel(intent: Intent) {
        val coordinator = intent.getStringExtra(EXTRA_COORDINATOR) ?: return
        val deviceName  = intent.getStringExtra(EXTRA_DEVICE_NAME) ?: "ferrum-android"
        val stunServer  = intent.getStringExtra(EXTRA_STUN_SERVER)
        val relay       = intent.getStringExtra(EXTRA_RELAY)
        val dnsOverride = intent.getStringExtra(EXTRA_DNS)
        val ipv6Policy  = intent.getStringExtra(EXTRA_IPV6_POLICY)

        val keystore   = KeystoreHelper(this)
        val prefs      = getSharedPreferences("ferrum_prefs", MODE_PRIVATE)
        val publicKey  = prefs.getString("public_key", null) ?: run {
            _state.value = ConnectionState.FAILED
            return
        }
        val privateKey = keystore.loadPrivateKey() ?: run {
            _state.value = ConnectionState.FAILED
            return
        }

        val identity = ClientIdentity(
            publicKey = publicKey,
            name      = deviceName,
            endpoint  = "",
            tags      = emptyList(),
        )

        startForeground(NOTIF_ID, buildNotification("Connecting…"))
        _state.value = ConnectionState.CONNECTING

        val c = FfiFerrumClient()
        client = c

        scope.launch {
            // Step 1: Control-plane connect to learn the coordinator-assigned address.
            try {
                c.connect(coordinator, identity)
            } catch (e: Exception) {
                _state.value = ConnectionState.FAILED
                updateNotification("Failed: ${e.message}")
                stopSelf()
                return@launch
            }

            // Step 2: Build the OS VPN interface with the correct assigned address.
            // Leak protection (PRD leak-protection.md M4): a local DNS override
            // wins, else whatever the coordinator advertised during connect —
            // the same local-else-advertised order as relay selection. IPv6 is
            // routed into the tunnel unless the policy is "off" (on Android,
            // routing ::/0 into a mesh that doesn't carry v6 *is* the block:
            // v6 blackholes instead of leaking around the tunnel).
            val dnsServers = dnsOverride
                ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
                ?.takeIf { it.isNotEmpty() }
                ?: c.advertisedDns()
            val routeIpv6 = ipv6Policy?.trim()?.lowercase() != "off"
            val assignedCidr = c.address()
            val fd = buildVpnInterface(assignedCidr, dnsServers, routeIpv6) ?: run {
                _state.value = ConnectionState.FAILED
                updateNotification("Failed to open TUN interface")
                stopSelf()
                return@launch
            }
            tun = fd
            _address.value = assignedCidr

            // Step 3: Event pump — translate Rust events → shared state flows.
            launch {
                while (isActive) {
                    when (val ev = c.nextEvent()) {
                        is ClientEvent.StateChanged   -> {
                            _state.value = ev.v1
                            _address.value = c.address()
                            updateNotification(stateLabel(ev.v1))
                        }
                        is ClientEvent.PeersUpdated   -> {
                            _peers.value = c.peers()
                            _address.value = c.address()
                        }
                        is ClientEvent.TrafficBlocked -> { /* kill-switch: no OS-level enforcement on Android */ }
                        is ClientEvent.Exception      -> updateNotification("Error: ${ev.v1}")
                        null                          -> break
                        else                          -> { /* future variants */ }
                    }
                }
            }

            // Step 4: Data plane — runs until stop() is called or tunnel drops.
            // Note: run() re-registers with the coordinator; the earlier connect()
            // call was used only to determine the assigned address for the TUN.
            try {
                c.run(
                    tunFd       = fd.detachFd(),
                    coordinator = coordinator,
                    identity    = identity,
                    privateKey  = privateKey,
                    listenPort  = 51820u,
                    stunServer  = stunServer,
                    relay       = relay,
                )
            } catch (e: Exception) {
                _state.value = ConnectionState.FAILED
                updateNotification("Failed: ${e.message}")
            } finally {
                stopSelf()
            }
        }
    }

    private fun stopTunnel() {
        client?.stop()
        client?.disconnect()
        scope.coroutineContext.cancelChildren()
        tun?.close()
        tun = null
        _state.value = ConnectionState.DISCONNECTED
        _peers.value = emptyList()
        _address.value = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        scope.cancel()
        super.onDestroy()
    }

    private fun buildVpnInterface(
        assignedCidr: String?,
        dnsServers: List<String>,
        routeIpv6: Boolean,
    ): ParcelFileDescriptor? {
        val builder = Builder().setSession("Ferrum VPN")
        if (assignedCidr != null) {
            // Parse "10.8.0.2/32" into address + prefix length.
            val parts = assignedCidr.split("/")
            val addr   = parts[0]
            val prefix = parts.getOrNull(1)?.toIntOrNull() ?: 32
            builder.addAddress(addr, prefix)
        } else {
            // Fallback: coordinator didn't return an address yet.
            builder.addAddress("10.100.0.2", 32)
        }
        builder.addRoute("0.0.0.0", 0)
        // "off" skips this route, letting v6 use the physical network; any
        // other policy sends v6 into the tunnel (carried if the mesh has v6,
        // blackholed — blocked, not leaked — if it doesn't).
        if (routeIpv6) builder.addRoute("::", 0)
        // With no resolver configured or advertised, an *empty* VPN DNS list
        // would make Android resolve via the underlying network — a plaintext
        // leak around the tunnel. Point at an in-tunnel sink instead: queries
        // fail visibly rather than leak silently (the pre-M4 hardcoded value,
        // now only a fallback).
        val servers = dnsServers.ifEmpty { listOf("1.1.1.1") }
        for (server in servers) {
            try {
                builder.addDnsServer(server)
            } catch (e: IllegalArgumentException) {
                // A malformed override entry — skip it rather than fail bring-up.
            }
        }
        return builder
            .setBlocking(false)
            .establish()
    }

    // ── Notifications ────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        val ch = NotificationChannel(NOTIF_CHANNEL, "VPN Status", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, NOTIF_CHANNEL)
            .setContentTitle("Ferrum VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(text))
    }

    private fun stateLabel(s: ConnectionState) = when (s) {
        ConnectionState.DISCONNECTED  -> "Disconnected"
        ConnectionState.CONNECTING    -> "Connecting…"
        ConnectionState.CONNECTED     -> "Connected"
        ConnectionState.RECONNECTING  -> "Reconnecting…"
        ConnectionState.FAILED        -> "Failed"
    }
}
