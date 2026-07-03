//! Kill-switch firewall enforcement (PRD Phase 5, FR5 — shell side).
//!
//! The shared core ([`ferrum_client_core::FerrumClient`]) decides *when* non-tunnel
//! traffic should be blocked — it emits [`ClientEvent::TrafficBlocked(bool)`] whenever
//! the derived signal (`kill-switch armed ∧ tunnel not Connected`) flips. This
//! module is the platform-specific half that *enforces* it: when the signal goes
//! true it installs leak-blocking firewall rules; when it goes false it removes
//! them.
//!
//! [`ClientEvent`]: ferrum_client_core::ClientEvent
//!
//! On Linux we drive `nftables` (`nft`) via [`ferrum_tunnel::firewall`] (shared
//! with the Phase 5 privileged-helper daemon so the rule generation and `nft`
//! invocation aren't duplicated): a dedicated `inet ferrum_killswitch` table
//! with an `output` chain whose policy is `drop`, accepting only loopback,
//! egress over the tunnel interface, and the coordinator endpoint(s) — so the
//! control plane can still reconnect while everything else is blocked. A dedicated
//! table makes teardown atomic (`nft delete table …`) and easy to clear by hand if
//! the app ever dies mid-engage. **This process tries the privileged helper
//! daemon first** ([`ask_helper`]), so it doesn't need to be root itself; it
//! only falls back to running `nft` in-process (needing this process to be
//! elevated) when the helper isn't reachable.
//!
//! On Windows we drive the **Windows Filtering Platform** (WFP) directly via the
//! `windows` crate: a dedicated provider + sublayer (our "namespace", the analog
//! of the Linux table) carries a default-block filter plus higher-weight permit
//! filters for loopback, the tunnel interface, and each coordinator/relay address,
//! installed at the `ALE_AUTH_CONNECT` v4/v6 layers. Teardown deletes exactly the
//! filters we added (tracked by their runtime ids) and then our sublayer/provider,
//! so it never touches unrelated WFP state. See the [`wfp`] module.
//!
//! On the remaining platforms (macOS) enforcement is not yet implemented; the
//! enforcer logs that the signal was observed but leaves the OS untouched (the UI
//! still reflects the intent via the `kill-switch` event). macOS (`pf`) is a
//! per-platform follow-up.

use std::net::IpAddr;

/// A single platform-neutral firewall rule the kill-switch needs installed. This
/// is the Windows analog of `ferrum_tunnel::firewall::engage_script`'s text: a
/// declarative description of the leak-block ruleset that the WFP layer
/// ([`wfp`]) translates into concrete filters, kept pure so the *rule logic*
/// is unit-testable without WFP or admin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub enum FilterSpec {
    /// Default-deny: block all outbound. Lowest weight, so any permit overrides it.
    BlockAll,
    /// Permit loopback (so local services keep working while traffic is blocked).
    AllowLoopback,
    /// Permit egress bound to the tunnel interface (named by OS alias).
    AllowInterface(String),
    /// Permit egress to one remote address — the coordinator/relay endpoints, so
    /// the control plane can still reconnect through the block.
    AllowRemote(IpAddr),
}

/// Build the ordered set of [`FilterSpec`]s that engage the kill-switch on `iface`,
/// permitting outbound only to loopback, the tunnel interface, and `allow_ips`.
/// Mirrors `ferrum_tunnel::firewall::engage_script` (Linux) but in a structured
/// form the WFP layer can consume. Pure (no I/O), so the rule logic is
/// unit-testable on any platform.
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub fn engage_filters(iface: &str, allow_ips: &[IpAddr]) -> Vec<FilterSpec> {
    let mut specs = vec![
        FilterSpec::BlockAll,
        FilterSpec::AllowLoopback,
        FilterSpec::AllowInterface(iface.to_string()),
    ];
    specs.extend(allow_ips.iter().copied().map(FilterSpec::AllowRemote));
    specs
}

/// Tracks whether the kill-switch firewall rules are currently installed, so the
/// enforcer only shells out on a real change and can tear down on exit.
#[derive(Default)]
pub struct KillSwitch {
    applied: bool,
    /// Runtime ids of the WFP filters we installed, so teardown removes exactly
    /// those and nothing else. `u64`/`Vec` keep `KillSwitch` `Send` (it lives in a
    /// `Mutex` in the Tauri-managed state) — we never hold a raw WFP engine handle.
    #[cfg(target_os = "windows")]
    filter_ids: Vec<u64>,
}

impl KillSwitch {
    /// Engage the kill-switch on `iface`, permitting outbound to `allow_ips`
    /// (typically the coordinator's resolved address[es]) in addition to loopback
    /// and the tunnel interface. Idempotent. A no-op success on platforms without
    /// an implementation (the signal is still surfaced to the UI).
    pub fn engage(&mut self, iface: &str, allow_ips: &[IpAddr]) {
        #[cfg(target_os = "linux")]
        {
            let req = ferrum_tunnel::helper_proto::HelperRequest::KillSwitchEngage {
                iface: iface.to_string(),
                allow_ips: allow_ips.iter().map(ToString::to_string).collect(),
            };
            let result = match ask_helper(req) {
                Some(r) => r,
                None => {
                    ferrum_tunnel::firewall::engage(iface, allow_ips).map_err(|e| e.to_string())
                }
            };
            match result {
                Ok(()) => {
                    self.applied = true;
                    log::info!(
                        "kill-switch engaged on {iface} ({} allowed)",
                        allow_ips.len()
                    );
                }
                Err(e) => log::error!("kill-switch engage failed: {e}"),
            }
        }
        #[cfg(target_os = "windows")]
        {
            match wfp::engage(&engage_filters(iface, allow_ips)) {
                Ok(ids) => {
                    self.filter_ids = ids;
                    self.applied = true;
                    log::info!(
                        "kill-switch engaged on {iface} ({} allowed)",
                        allow_ips.len()
                    );
                }
                // `wfp::engage` installs inside a WFP transaction, so a failure
                // aborts atomically — nothing is left half-applied to roll back.
                Err(e) => log::error!("kill-switch engage failed: {e}"),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = (iface, allow_ips);
            log::warn!(
                "kill-switch requested but firewall enforcement is not implemented on this platform"
            );
        }
    }

    /// Remove the kill-switch rules. Idempotent; safe to call when not engaged.
    pub fn disengage(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if !self.applied {
                return;
            }
            let result =
                match ask_helper(ferrum_tunnel::helper_proto::HelperRequest::KillSwitchDisengage) {
                    Some(r) => r,
                    None => ferrum_tunnel::firewall::disengage().map_err(|e| e.to_string()),
                };
            match result {
                Ok(()) => log::info!("kill-switch disengaged"),
                // A missing table on teardown is fine (already gone).
                Err(e) => log::warn!("kill-switch disengage: {e}"),
            }
            self.applied = false;
        }
        #[cfg(target_os = "windows")]
        {
            if !self.applied {
                return;
            }
            match wfp::disengage(&self.filter_ids) {
                Ok(()) => log::info!("kill-switch disengaged"),
                Err(e) => log::warn!("kill-switch disengage: {e}"),
            }
            self.filter_ids.clear();
            self.applied = false;
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            self.applied = false;
        }
    }

    /// Whether the rules are currently installed.
    // Exposed for tests/diagnostics; not read on the main path.
    #[allow(dead_code)]
    pub fn is_applied(&self) -> bool {
        self.applied
    }
}

/// Best-effort teardown on drop, so a crash/exit doesn't strand the network in a
/// blocked state. (Tauri does not guarantee managed-state `Drop` on exit, so the
/// app also disengages explicitly on `RunEvent::Exit`.)
impl Drop for KillSwitch {
    fn drop(&mut self) {
        self.disengage();
    }
}

/// Ask the privileged helper daemon (Phase 5) to run `req`, if it's reachable.
///
/// Returns `None` when the helper's socket can't be connected to at all (no
/// daemon installed/running) — the caller falls back to doing the privileged
/// operation in-process. Returns `Some(Err(_))` only when the helper *is*
/// reachable but the operation itself failed (or the protocol broke), so a
/// real failure is surfaced rather than silently retried in-process.
#[cfg(target_os = "linux")]
fn ask_helper(req: ferrum_tunnel::helper_proto::HelperRequest) -> Option<Result<(), String>> {
    use ferrum_tunnel::helper_proto::{recv_response, send_request, HelperResponse};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(crate::HELPER_SOCK_PATH).ok()?;
    if let Err(e) = send_request(&mut stream, &req) {
        return Some(Err(e.to_string()));
    }
    Some(match recv_response(&stream) {
        Ok((HelperResponse::Ok, _)) => Ok(()),
        Ok((HelperResponse::Err(msg), _)) => Err(msg),
        Ok((HelperResponse::TunOpened, _)) => {
            Err("helper sent an unexpected TunOpened response".to_string())
        }
        Err(e) => Err(e.to_string()),
    })
}

/// Windows Filtering Platform (WFP) enforcement of the kill-switch.
///
/// We install our rules under a dedicated **provider** + **sublayer** (our
/// namespace — the analog of the Linux `nft` table). [`engage`] adds, inside a WFP
/// transaction, a default-`BLOCK` filter plus higher-weight `PERMIT` filters for
/// loopback, the tunnel interface, and each coordinator/relay address, at the
/// `ALE_AUTH_CONNECT` v4/v6 layers. Within one sublayer the highest-weight matching
/// filter wins, so the permits override the block. [`disengage`] deletes exactly the
/// filters we added (by the runtime ids `engage` returned) and then our sublayer and
/// provider, leaving unrelated WFP state untouched.
///
/// All filter installs/deletes run in a transaction, so a mid-way failure aborts
/// atomically — nothing is left half-applied. Rules are *not* auto-removed if the
/// process dies mid-engage (same as the Linux table); [`KillSwitch::disengage`] on
/// drop / app-exit and on the release signal handles teardown.
#[cfg(target_os = "windows")]
mod wfp {
    use super::FilterSpec;
    use std::net::IpAddr;
    use windows::core::{Result, GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{FWP_E_ALREADY_EXISTS, HANDLE, WIN32_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    // Stable keys identifying our provider + sublayer (our private WFP namespace,
    // like the dedicated `nft` table on Linux). Distinct random GUIDs.
    const PROVIDER_KEY: GUID = GUID::from_u128(0xfe110a73_5b2c_4d8e_9f01_a2b3c4d5e6f7);
    const SUBLAYER_KEY: GUID = GUID::from_u128(0xfe110a73_5b2c_4d8e_9f02_a2b3c4d5e6f7);

    // Weights within our sublayer: permits beat the catch-all block.
    const WEIGHT_BLOCK: u8 = 0;
    const WEIGHT_PERMIT: u8 = 10;

    // FwpmEngineOpen0 authentication service: Windows authentication (RPC_C_AUTHN_WINNT).
    const RPC_C_AUTHN_WINNT: u32 = 10;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The `Fwpm*` functions return a raw `WIN32_ERROR` code as `u32`; map it to a
    /// `Result` (0 == `ERROR_SUCCESS`).
    fn check(rc: u32) -> Result<()> {
        WIN32_ERROR(rc).ok()
    }

    /// Engage the kill-switch by installing `specs` as WFP filters. Returns the
    /// runtime ids of the installed filters (for [`disengage`]).
    pub fn engage(specs: &[FilterSpec]) -> Result<Vec<u64>> {
        unsafe {
            let mut engine = HANDLE::default();
            check(FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                None,
                &mut engine,
            ))?;

            let result = install(engine, specs);

            if result.is_err() {
                // Roll back the whole batch; nothing committed.
                let _ = FwpmTransactionAbort0(engine);
            }
            let _ = FwpmEngineClose0(engine);
            result
        }
    }

    unsafe fn install(engine: HANDLE, specs: &[FilterSpec]) -> Result<Vec<u64>> {
        check(FwpmTransactionBegin0(engine, 0))?;
        ensure_provider(engine)?;
        ensure_sublayer(engine)?;

        let mut ids = Vec::new();
        for spec in specs {
            add_spec(engine, spec, &mut ids)?;
        }

        check(FwpmTransactionCommit0(engine))?;
        Ok(ids)
    }

    /// Add the filter(s) for one spec. Backing storage for pointer-valued condition
    /// values (the v6 address, the interface LUID) lives in this stack frame and
    /// stays valid across the synchronous `FwpmFilterAdd0` call inside `add_one`.
    unsafe fn add_spec(engine: HANDLE, spec: &FilterSpec, ids: &mut Vec<u64>) -> Result<()> {
        match spec {
            FilterSpec::BlockAll => {
                for layer in [
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                ] {
                    ids.push(add_one(engine, layer, FWP_ACTION_BLOCK, WEIGHT_BLOCK, &[])?);
                }
            }
            FilterSpec::AllowLoopback => {
                let cond = [flag_cond(
                    FWPM_CONDITION_FLAGS,
                    FWP_CONDITION_FLAG_IS_LOOPBACK,
                )];
                for layer in [
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                ] {
                    ids.push(add_one(
                        engine,
                        layer,
                        FWP_ACTION_PERMIT,
                        WEIGHT_PERMIT,
                        &cond,
                    )?);
                }
            }
            FilterSpec::AllowInterface(alias) => match alias_to_luid(alias) {
                Some(mut luid) => {
                    let cond = [uint64_cond(FWPM_CONDITION_IP_LOCAL_INTERFACE, &mut luid)];
                    for layer in [
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    ] {
                        ids.push(add_one(
                            engine,
                            layer,
                            FWP_ACTION_PERMIT,
                            WEIGHT_PERMIT,
                            &cond,
                        )?);
                    }
                }
                // The tunnel adapter may not exist yet (e.g. before the data plane
                // is up, or on a host without the Windows TUN). Loopback + the
                // coordinator allowlist still let the control plane reconnect.
                None => log::debug!(
                    "kill-switch: tunnel interface {alias} not present; skipping interface permit"
                ),
            },
            FilterSpec::AllowRemote(IpAddr::V4(v4)) => {
                let cond = [uint32_cond(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    u32::from(*v4),
                )];
                ids.push(add_one(
                    engine,
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWP_ACTION_PERMIT,
                    WEIGHT_PERMIT,
                    &cond,
                )?);
            }
            FilterSpec::AllowRemote(IpAddr::V6(v6)) => {
                let mut bytes = FWP_BYTE_ARRAY16 {
                    byteArray16: v6.octets(),
                };
                let cond = [bytearray16_cond(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    &mut bytes,
                )];
                ids.push(add_one(
                    engine,
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    FWP_ACTION_PERMIT,
                    WEIGHT_PERMIT,
                    &cond,
                )?);
            }
        }
        Ok(())
    }

    unsafe fn add_one(
        engine: HANDLE,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        weight: u8,
        conds: &[FWPM_FILTER_CONDITION0],
    ) -> Result<u64> {
        let mut name = wide("Ferrum kill-switch");
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR::null(),
            },
            providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
            layerKey: layer,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: conds.len() as u32,
            filterCondition: conds.as_ptr() as *mut FWPM_FILTER_CONDITION0,
            action: FWPM_ACTION0 {
                r#type: action,
                Anonymous: FWPM_ACTION0_0::default(),
            },
            ..Default::default()
        };
        let mut id = 0u64;
        check(FwpmFilterAdd0(engine, &filter, None, Some(&mut id)))?;
        Ok(id)
    }

    /// Disengage by deleting the filters we installed (by id), then our sublayer and
    /// provider. Idempotent: a missing object on teardown is fine (already gone).
    pub fn disengage(filter_ids: &[u64]) -> Result<()> {
        unsafe {
            let mut engine = HANDLE::default();
            check(FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                None,
                &mut engine,
            ))?;

            let result = remove(engine, filter_ids);

            if result.is_err() {
                let _ = FwpmTransactionAbort0(engine);
            }
            let _ = FwpmEngineClose0(engine);
            result
        }
    }

    unsafe fn remove(engine: HANDLE, filter_ids: &[u64]) -> Result<()> {
        check(FwpmTransactionBegin0(engine, 0))?;
        for &id in filter_ids {
            // Ignore not-found so teardown is idempotent after a partial/stale state.
            let _ = FwpmFilterDeleteById0(engine, id);
        }
        let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_KEY);
        let _ = FwpmProviderDeleteByKey0(engine, &PROVIDER_KEY);
        check(FwpmTransactionCommit0(engine))?;
        Ok(())
    }

    unsafe fn ensure_provider(engine: HANDLE) -> Result<()> {
        let mut name = wide("Ferrum Kill-Switch");
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR::null(),
            },
            ..Default::default()
        };
        ignore_already_exists(FwpmProviderAdd0(engine, &provider, None))
    }

    unsafe fn ensure_sublayer(engine: HANDLE) -> Result<()> {
        let mut name = wide("Ferrum Kill-Switch");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR::null(),
            },
            providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
            weight: 0x100,
            ..Default::default()
        };
        ignore_already_exists(FwpmSubLayerAdd0(engine, &sublayer, None))
    }

    /// Treat `FWP_E_ALREADY_EXISTS` as success — re-engaging reuses our persistent
    /// provider/sublayer rather than recreating them.
    fn ignore_already_exists(rc: u32) -> Result<()> {
        match check(rc) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == FWP_E_ALREADY_EXISTS => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Resolve a network-interface alias (e.g. `"ferrum0"`) to its LUID, or `None`
    /// if the adapter isn't present.
    fn alias_to_luid(alias: &str) -> Option<u64> {
        let w = wide(alias);
        let mut luid = NET_LUID_LH::default();
        let rc = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(w.as_ptr()), &mut luid) };
        rc.ok().ok().map(|()| unsafe { luid.Value })
    }

    fn uint32_cond(field: GUID, val: u32) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint32: val },
            },
        }
    }

    fn flag_cond(field: GUID, flag: u32) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_FLAGS_ALL_SET,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint32: flag },
            },
        }
    }

    fn uint64_cond(field: GUID, val: *mut u64) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint64: val },
            },
        }
    }

    fn bytearray16_cond(field: GUID, val: *mut FWP_BYTE_ARRAY16) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteArray16: val },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engage_filters_blocks_by_default_and_allows_loopback_and_iface() {
        let specs = engage_filters("ferrum0", &[]);
        // A default-block plus permits for loopback and the tunnel interface.
        assert_eq!(
            specs[0],
            FilterSpec::BlockAll,
            "first rule must be the catch-all block"
        );
        assert!(specs.contains(&FilterSpec::AllowLoopback));
        assert!(specs.contains(&FilterSpec::AllowInterface("ferrum0".into())));
        // With no allowlisted endpoints, those three are the whole ruleset.
        assert_eq!(specs.len(), 3);
    }

    #[test]
    fn engage_filters_allowlists_coordinator_addresses() {
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let specs = engage_filters("ferrum0", &[v4, v6]);
        assert!(specs.contains(&FilterSpec::AllowRemote(v4)));
        assert!(specs.contains(&FilterSpec::AllowRemote(v6)));
    }

    #[test]
    fn killswitch_tracks_applied_state_on_unsupported_platforms() {
        // On non-Linux the calls are no-ops; `applied` only flips on Linux. This
        // exercises the state machine without requiring `nft`.
        let mut ks = KillSwitch::default();
        assert!(!ks.is_applied());
        ks.disengage(); // safe when never engaged
        assert!(!ks.is_applied());
    }
}
