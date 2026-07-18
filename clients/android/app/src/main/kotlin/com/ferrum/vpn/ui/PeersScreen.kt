package com.ferrum.vpn.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.ferrum.vpn.VpnViewModel
import uniffi.ferrum_client_core.PeerPath
import uniffi.ferrum_client_core.PeerStatus

@Composable
fun PeersScreen(vm: VpnViewModel) {
    val ui by vm.ui.collectAsState()

    if (ui.peers.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("No peers connected", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        return
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(ui.peers) { peer -> PeerCard(peer) }
    }
}

@Composable
private fun PeerCard(peer: PeerStatus) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val (icon, tint) = when (peer.path) {
                PeerPath.DIRECT  -> Icons.Default.Wifi   to MaterialTheme.colorScheme.primary
                PeerPath.RELAY   -> Icons.Default.Router to MaterialTheme.colorScheme.tertiary
                PeerPath.UNKNOWN -> Icons.Default.Wifi   to MaterialTheme.colorScheme.outlineVariant
            }
            Icon(imageVector = icon, contentDescription = null, tint = tint)
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    text = peer.publicKey.take(16) + "…",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                )
                peer.endpoint?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text(
                    text = peer.allowedIps.joinToString(", "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Badge(containerColor = when (peer.path) {
                PeerPath.DIRECT  -> MaterialTheme.colorScheme.primaryContainer
                PeerPath.RELAY   -> MaterialTheme.colorScheme.tertiaryContainer
                PeerPath.UNKNOWN -> MaterialTheme.colorScheme.surfaceVariant
            }) {
                Text(when (peer.path) {
                    PeerPath.DIRECT  -> "Direct"
                    PeerPath.RELAY   -> "Relay"
                    PeerPath.UNKNOWN -> "?"
                })
            }
        }
    }
}
