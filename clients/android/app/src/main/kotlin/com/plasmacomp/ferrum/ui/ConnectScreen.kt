package com.plasmacomp.ferrum.ui

import android.app.Activity
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.plasmacomp.ferrum.VpnViewModel
import uniffi.ferrum_client_core.ConnectionState

@Composable
fun ConnectScreen(vm: VpnViewModel) {
    val ui by vm.ui.collectAsState()
    val ctx = LocalContext.current

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) vm.connect(ctx)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(48.dp))

        // Status indicator
        StatusIndicator(ui.connectionState)

        Spacer(Modifier.height(8.dp))

        Text(
            text = stateLabel(ui.connectionState),
            fontSize = 20.sp,
            fontWeight = FontWeight.SemiBold,
        )

        ui.address?.let {
            Text(text = it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        Spacer(Modifier.height(40.dp))

        OutlinedTextField(
            value = ui.coordinator,
            onValueChange = vm::setCoordinator,
            label = { Text("Coordinator address") },
            placeholder = { Text("coordinator.example.com:50051") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(32.dp))

        val connected = ui.connectionState == ConnectionState.CONNECTED ||
                        ui.connectionState == ConnectionState.RECONNECTING

        Button(
            onClick = {
                if (connected) {
                    vm.disconnect(ctx)
                } else {
                    val permIntent = vm.prepareVpnIntent(ctx)
                    if (permIntent != null) vpnPermissionLauncher.launch(permIntent)
                    else vm.connect(ctx)
                }
            },
            enabled = ui.connectionState != ConnectionState.CONNECTING,
            colors = if (connected) ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error
            ) else ButtonDefaults.buttonColors(),
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
        ) {
            Text(if (connected) "Disconnect" else "Connect", fontSize = 18.sp)
        }
    }
}

@Composable
private fun StatusIndicator(state: ConnectionState) {
    val color = when (state) {
        ConnectionState.CONNECTED     -> MaterialTheme.colorScheme.primary
        ConnectionState.CONNECTING,
        ConnectionState.RECONNECTING  -> MaterialTheme.colorScheme.tertiary
        ConnectionState.FAILED        -> MaterialTheme.colorScheme.error
        ConnectionState.DISCONNECTED  -> MaterialTheme.colorScheme.outlineVariant
    }
    val icon = when (state) {
        ConnectionState.CONNECTED    -> Icons.Default.Shield
        ConnectionState.CONNECTING,
        ConnectionState.RECONNECTING -> Icons.Default.Sync
        ConnectionState.FAILED       -> Icons.Default.Error
        ConnectionState.DISCONNECTED -> Icons.Default.ShieldOutlined
    }
    Icon(imageVector = icon, contentDescription = null, tint = color, modifier = Modifier.size(80.dp))
}

private fun stateLabel(s: ConnectionState) = when (s) {
    ConnectionState.DISCONNECTED  -> "Disconnected"
    ConnectionState.CONNECTING    -> "Connecting…"
    ConnectionState.CONNECTED     -> "Connected"
    ConnectionState.RECONNECTING  -> "Reconnecting…"
    ConnectionState.FAILED        -> "Connection Failed"
}
