//! Access control for the helper service's named pipe (SEC-005, Windows).
//!
//! The [`crate::service`] pipe is the trust boundary between the unprivileged GUI
//! and a LocalSystem service that brings up wintun adapters and rewrites WFP
//! filters, so who may open it matters. Two independent layers enforce it:
//!
//! 1. **An explicit pipe DACL** ([`PIPE_SDDL`]) instead of the default security
//!    descriptor (which grants read to Everyone and Anonymous). SYSTEM,
//!    Administrators and the pipe's owner get full control; interactive users get
//!    read/write **without `FILE_CREATE_PIPE_INSTANCE`** (the same bit as
//!    `FILE_APPEND_DATA`, which `GENERIC_WRITE` would include), so they can't add
//!    their own instances of the pipe name and race the service for GUI clients.
//!    Network logons are denied outright, and the medium mandatory label keeps
//!    low-integrity / sandboxed processes from writing. The pipe is also created
//!    with `PIPE_REJECT_REMOTE_CLIENTS`.
//! 2. **A post-connect identity check** ([`verify_client`]): the service
//!    impersonates the connected client just long enough to open its token and
//!    checks membership against a [`ClientPolicy`] — the same principals the DACL
//!    admits — so a mistake or a future loosening in one layer doesn't open the
//!    boundary alone. The kernel attests this identity; the client can't claim it.

#![cfg(windows)]

use std::ffi::c_void;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::{BOOL, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, RevertToSelf, WinBuiltinAdministratorsSid,
    WinInteractiveSid, WinLocalSystemSid, WinNetworkSid, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, WELL_KNOWN_SID_TYPE,
};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

/// The helper pipe's security descriptor, in SDDL.
///
/// * `D:P` — a protected DACL (nothing inherited).
/// * `(D;;GA;;;NU)` — deny network logons (defence in depth next to
///   `PIPE_REJECT_REMOTE_CLIENTS`).
/// * `(A;;GA;;;SY)` / `(A;;GA;;;BA)` — LocalSystem and (elevated) Administrators.
/// * `(A;;GA;;;OW)` — the pipe's owner, i.e. the process that created it: the
///   service itself, which must be able to create further instances.
/// * `(A;;0x12019b;;;IU)` — interactive users: `FILE_GENERIC_READ |
///   FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES` — enough to connect
///   and talk, but deliberately **not** `FILE_CREATE_PIPE_INSTANCE` (0x4).
/// * `S:(ML;;NW;;;ME)` — medium mandatory label, no-write-up.
pub const PIPE_SDDL: &str =
    "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12019b;;;IU)S:(ML;;NW;;;ME)";

/// The access mask [`PIPE_SDDL`] grants interactive users (see there).
pub const INTERACTIVE_ACCESS: u32 = 0x0012_019b;

/// `FILE_CREATE_PIPE_INSTANCE` (== `FILE_APPEND_DATA`): creating a new instance of
/// an existing pipe name. Only the service may hold it.
pub const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0000_0004;

/// Who the post-connect check admits: a caller whose token is a member of at least
/// one `allow` SID and of no `deny` SID. Membership follows `CheckTokenMembership`
/// semantics, so a filtered (non-elevated) admin token's deny-only Administrators
/// SID doesn't count — such a caller is admitted as an interactive user instead.
#[derive(Debug, Clone)]
pub struct ClientPolicy {
    pub allow: Vec<WELL_KNOWN_SID_TYPE>,
    pub deny: Vec<WELL_KNOWN_SID_TYPE>,
}

impl Default for ClientPolicy {
    /// The principals [`PIPE_SDDL`] admits: SYSTEM, Administrators, interactive
    /// users; never a network logon.
    fn default() -> Self {
        Self {
            allow: vec![
                WinLocalSystemSid,
                WinBuiltinAdministratorsSid,
                WinInteractiveSid,
            ],
            deny: vec![WinNetworkSid],
        }
    }
}

/// Pipe access configuration for [`crate::service`]: the DACL the pipe is created
/// with plus the policy each connected client is checked against.
#[derive(Debug, Clone)]
pub struct PipeAccess {
    pub sddl: String,
    pub policy: ClientPolicy,
}

impl Default for PipeAccess {
    fn default() -> Self {
        Self {
            sddl: PIPE_SDDL.to_owned(),
            policy: ClientPolicy::default(),
        }
    }
}

/// A security descriptor parsed from SDDL, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call;
        // `sd` receives a LocalAlloc'd descriptor that `Drop` frees.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .map_err(|e| std::io::Error::other(format!("invalid pipe SDDL {sddl:?}: {e}")))?;
        Ok(Self(sd))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW,
        // freed exactly once.
        unsafe {
            LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

/// Create one instance of `pipe_name` secured by `sddl`, rejecting remote clients.
/// `first` sets `FILE_FLAG_FIRST_PIPE_INSTANCE`, so creation fails if anyone else
/// already owns the name (squatting protection).
pub fn create_pipe(pipe_name: &str, first: bool, sddl: &str) -> std::io::Result<NamedPipeServer> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0 .0,
        bInheritHandle: false.into(),
    };
    // SAFETY: `attrs` is a fully initialized SECURITY_ATTRIBUTES whose descriptor
    // (`sd`) stays alive until after the call returns; CreateNamedPipeW copies it.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                pipe_name,
                &mut attrs as *mut SECURITY_ATTRIBUTES as *mut c_void,
            )
    }
}

/// What the service learned about an admitted client (for logging).
#[derive(Debug, Clone, Copy)]
pub struct ClientInfo {
    pub pid: u32,
}

/// An owned kernel handle, closed on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: a handle this module opened, closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Verify the client connected to `pipe` against `policy`.
///
/// Returns the client's pid on success; on refusal, a reason suitable for a log
/// line (the client itself should only be told "not authorized").
pub fn verify_client(pipe: &NamedPipeServer, policy: &ClientPolicy) -> Result<ClientInfo, String> {
    use std::os::windows::io::AsRawHandle;
    let handle = HANDLE(pipe.as_raw_handle());

    let mut pid = 0u32;
    // SAFETY: `handle` is the live server end of a connected pipe.
    unsafe { GetNamedPipeClientProcessId(handle, &mut pid) }
        .map_err(|e| format!("querying client pid: {e}"))?;

    let token = client_token(handle).map_err(|e| format!("client pid {pid}: {e}"))?;
    let is_member = |sid_type: WELL_KNOWN_SID_TYPE| -> Result<bool, String> {
        token_is_member(&token, sid_type).map_err(|e| format!("client pid {pid}: {e}"))
    };
    for &sid in &policy.deny {
        if is_member(sid)? {
            return Err(format!(
                "client pid {pid} is a member of denied SID {sid:?}"
            ));
        }
    }
    for &sid in &policy.allow {
        if is_member(sid)? {
            return Ok(ClientInfo { pid });
        }
    }
    Err(format!(
        "client pid {pid} is not a member of any allowed SID {:?}",
        policy.allow
    ))
}

/// Open the connected client's token by briefly impersonating it on this thread.
///
/// Works at the `SecurityIdentification` level tokio's `ClientOptions` requests by
/// default (identification is enough to open and query a token). A client that
/// opened with `SECURITY_ANONYMOUS` yields the anonymous token, which matches no
/// allowed SID — refused, fail-closed.
fn client_token(pipe: HANDLE) -> Result<OwnedHandle, String> {
    // SAFETY: `pipe` is a connected server handle. The impersonation is confined to
    // this synchronous function: nothing between Impersonate and RevertToSelf can
    // yield the thread, and a failed revert aborts rather than leave a runtime
    // worker thread running as the client.
    unsafe {
        ImpersonateNamedPipeClient(pipe).map_err(|e| format!("impersonating client: {e}"))?;
        let mut token = HANDLE::default();
        // `OpenAsSelf`: the access check to open the token uses the service's own
        // identity, not the (possibly identification-only) client's.
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token);
        if RevertToSelf().is_err() {
            log::error!("RevertToSelf failed after impersonating a helper client; aborting");
            std::process::abort();
        }
        opened.map_err(|e| format!("opening client token: {e}"))?;
        Ok(OwnedHandle(token))
    }
}

/// `CheckTokenMembership` against a well-known SID (enabled SIDs only; deny-only
/// SIDs don't count).
fn token_is_member(token: &OwnedHandle, sid_type: WELL_KNOWN_SID_TYPE) -> Result<bool, String> {
    // SECURITY_MAX_SID_SIZE; u32-aligned for the SID structure.
    let mut buf = [0u32; 17];
    let mut size = std::mem::size_of_val(&buf) as u32;
    let sid = PSID(buf.as_mut_ptr() as *mut c_void);
    let mut member = BOOL(0);
    // SAFETY: `buf` is large enough for any SID and outlives both calls; `token`
    // is an impersonation token opened with TOKEN_QUERY.
    unsafe {
        CreateWellKnownSid(sid_type, None, Some(sid), &mut size)
            .map_err(|e| format!("building SID {sid_type:?}: {e}"))?;
        CheckTokenMembership(Some(token.0), sid, &mut member)
            .map_err(|e| format!("checking membership of {sid_type:?}: {e}"))?;
    }
    Ok(member.as_bool())
}

/// Whether the calling process's own token is a member of `sid_type` (tests use
/// it to skip cases whose outcome depends on how they were launched).
#[cfg(test)]
pub(crate) fn current_process_is_member(sid_type: WELL_KNOWN_SID_TYPE) -> bool {
    let mut buf = [0u32; 17];
    let mut size = std::mem::size_of_val(&buf) as u32;
    let sid = PSID(buf.as_mut_ptr() as *mut c_void);
    let mut member = BOOL(0);
    // SAFETY: as in `token_is_member`; `None` checks the caller's own token.
    unsafe {
        CreateWellKnownSid(sid_type, None, Some(sid), &mut size).unwrap();
        CheckTokenMembership(None, sid, &mut member).unwrap();
    }
    member.as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_sddl_parses() {
        SecurityDescriptor::from_sddl(PIPE_SDDL).unwrap();
    }

    #[test]
    fn malformed_sddl_is_an_error_not_a_default_descriptor() {
        assert!(SecurityDescriptor::from_sddl("D:P(A;;GA;;;NOT_A_SID)").is_err());
        let err = create_pipe(r"\\.\pipe\ferrum-helper-test-bad-sddl", true, "garbage")
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid pipe SDDL"), "{err}");
    }

    /// Interactive users can read and write but never create pipe instances, and
    /// their ACE uses explicit rights (no generic bits that would map to
    /// `FILE_APPEND_DATA`).
    #[test]
    fn interactive_users_cannot_create_pipe_instances() {
        assert!(PIPE_SDDL.contains(&format!("(A;;{INTERACTIVE_ACCESS:#x};;;IU)")));
        assert_eq!(INTERACTIVE_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
        const GENERIC_ALL_WRITE: u32 = 0xF000_0000;
        assert_eq!(INTERACTIVE_ACCESS & GENERIC_ALL_WRITE, 0);
        // FILE_READ_DATA | FILE_WRITE_DATA, the two a client actually needs.
        assert_eq!(INTERACTIVE_ACCESS & 0x3, 0x3);
    }

    #[test]
    fn default_policy_matches_the_dacl_principals() {
        let p = ClientPolicy::default();
        assert_eq!(
            p.allow,
            vec![
                WinLocalSystemSid,
                WinBuiltinAdministratorsSid,
                WinInteractiveSid
            ]
        );
        assert_eq!(p.deny, vec![WinNetworkSid]);
        for ace in ["(A;;GA;;;SY)", "(A;;GA;;;BA)", ";;;IU)", "(D;;GA;;;NU)"] {
            assert!(PIPE_SDDL.contains(ace), "{ace}");
        }
    }
}
