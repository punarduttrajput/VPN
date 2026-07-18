package com.ferrum.vpn

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.ferrum.vpn.ui.ConnectScreen
import com.ferrum.vpn.ui.PeersScreen
import com.ferrum.vpn.ui.SettingsScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            FerrumTheme {
                FerrumApp()
            }
        }
    }
}

@Composable
fun FerrumApp(vm: VpnViewModel = viewModel()) {
    val nav = rememberNavController()
    val backStack by nav.currentBackStackEntryAsState()
    val current = backStack?.destination?.route ?: "connect"

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = current == "connect",
                    onClick = { nav.navigate("connect") { launchSingleTop = true } },
                    icon = { Icon(Icons.Default.Shield, null) },
                    label = { Text("Connect") },
                )
                NavigationBarItem(
                    selected = current == "peers",
                    onClick = { nav.navigate("peers") { launchSingleTop = true } },
                    icon = { Icon(Icons.Default.People, null) },
                    label = { Text("Peers") },
                )
                NavigationBarItem(
                    selected = current == "settings",
                    onClick = { nav.navigate("settings") { launchSingleTop = true } },
                    icon = { Icon(Icons.Default.Settings, null) },
                    label = { Text("Settings") },
                )
            }
        }
    ) { inner ->
        NavHost(
            navController = nav,
            startDestination = "connect",
            modifier = Modifier.padding(inner),
        ) {
            composable("connect")  { ConnectScreen(vm) }
            composable("peers")    { PeersScreen(vm) }
            composable("settings") { SettingsScreen(vm) }
        }
    }
}

@Composable
fun FerrumTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = dynamicColorScheme(),
        content = content,
    )
}

@Composable
private fun dynamicColorScheme(): ColorScheme {
    // Use Material You dynamic color on API 31+, static fallback otherwise.
    return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
        val ctx = androidx.compose.ui.platform.LocalContext.current
        androidx.compose.material3.dynamicDarkColorScheme(ctx)
    } else {
        darkColorScheme()
    }
}
