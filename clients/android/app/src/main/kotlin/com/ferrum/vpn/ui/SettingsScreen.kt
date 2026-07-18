package com.ferrum.vpn.ui

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.ferrum.vpn.Curve25519Keygen
import com.ferrum.vpn.KeystoreHelper
import com.ferrum.vpn.VpnViewModel

@Composable
fun SettingsScreen(vm: VpnViewModel) {
    val ui by vm.ui.collectAsState()
    val ctx = LocalContext.current
    val keystore = remember { KeystoreHelper(ctx) }
    var hasKey by remember { mutableStateOf(keystore.hasPrivateKey()) }
    var showKeygenConfirm by remember { mutableStateOf(false) }
    var hasToken by remember { mutableStateOf(keystore.hasToken()) }
    var tokenInput by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall)

        OutlinedTextField(
            value = ui.deviceName,
            onValueChange = vm::setDeviceName,
            label = { Text("Device name") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = ui.stunServer,
            onValueChange = vm::setStunServer,
            label = { Text("STUN server (optional)") },
            placeholder = { Text("stun.example.com:3478") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = ui.relay,
            onValueChange = vm::setRelay,
            label = { Text("Relay override (optional)") },
            placeholder = { Text("relay.example.com:3478") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = ui.dnsServers,
            onValueChange = vm::setDnsServers,
            label = { Text("DNS override (optional)") },
            placeholder = { Text("10.99.0.53, fd00::53") },
            supportingText = { Text("Empty = use the resolvers the coordinator advertises") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = ui.ipv6Policy,
            onValueChange = vm::setIpv6Policy,
            label = { Text("IPv6 policy (optional)") },
            placeholder = { Text("auto | block | tunnel | off") },
            supportingText = { Text("Anything but \"off\" keeps IPv6 inside the tunnel") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text("Kill switch", style = MaterialTheme.typography.bodyLarge)
                Text(
                    "Block traffic when tunnel is down",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(checked = ui.killSwitch, onCheckedChange = vm::setKillSwitch)
        }

        HorizontalDivider()

        Text("Coordinator token", style = MaterialTheme.typography.titleMedium)
        Text(
            "Required if the coordinator was built with --oidc-issuer — paste a " +
                "device token minted with mint-token.py (or your IdP). Stored in the " +
                "Android Keystore, same as the device private key.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (hasToken) {
            Text("A token is stored.", style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = {
                keystore.clearToken()
                hasToken = false
            }) { Text("Clear token") }
        } else {
            OutlinedTextField(
                value = tokenInput,
                onValueChange = { tokenInput = it },
                label = { Text("Bearer token") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = {
                    keystore.saveToken(tokenInput)
                    tokenInput = ""
                    hasToken = true
                },
                enabled = tokenInput.isNotBlank(),
            ) { Text("Save token") }
        }

        HorizontalDivider()

        Text("Device key", style = MaterialTheme.typography.titleMedium)

        if (hasKey) {
            Text("A private key is stored in the Android Keystore.", style = MaterialTheme.typography.bodyMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { showKeygenConfirm = true }) { Text("Regenerate key") }
                OutlinedButton(onClick = {
                    keystore.clearPrivateKey()
                    clearPublicKey(ctx)
                    hasKey = false
                }) { Text("Remove key") }
            }
        } else {
            Text("No key stored. Generate one to connect.", style = MaterialTheme.typography.bodyMedium)
            Button(onClick = { generateAndStoreKey(ctx, keystore); hasKey = true }) {
                Text("Generate key pair")
            }
        }
    }

    if (showKeygenConfirm) {
        AlertDialog(
            onDismissRequest = { showKeygenConfirm = false },
            title = { Text("Regenerate key?") },
            text = { Text("The coordinator will need to re-register the new public key. Existing sessions will drop.") },
            confirmButton = {
                TextButton(onClick = {
                    generateAndStoreKey(ctx, keystore)
                    showKeygenConfirm = false
                    hasKey = true
                }) { Text("Regenerate") }
            },
            dismissButton = {
                TextButton(onClick = { showKeygenConfirm = false }) { Text("Cancel") }
            },
        )
    }
}

private fun generateAndStoreKey(ctx: Context, keystore: KeystoreHelper) {
    // Delegate key generation to the Rust core so the same crypto path is used everywhere.
    // This calls `ferrum keygen` equivalently via the uniffi API surface.
    // For the bootstrap path we derive using BouncyCastle/conscrypt via the NDK's Curve25519.
    // Full solution: call FfiFerrumClient.generateKeypair() once that method is exposed.
    // For now: generate with a simple Curve25519 keygen shim, store result.
    val (priv, pub) = Curve25519Keygen.generate()
    keystore.savePrivateKey(priv)
    ctx.getSharedPreferences("ferrum_prefs", Context.MODE_PRIVATE)
        .edit().putString("public_key", pub).apply()
}

private fun clearPublicKey(ctx: Context) {
    ctx.getSharedPreferences("ferrum_prefs", Context.MODE_PRIVATE)
        .edit().remove("public_key").apply()
}
