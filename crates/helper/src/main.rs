//! `ferrum-helper` — the Phase 5 privileged helper daemon.
//!
//! Splits the two privileged operations the Ferrum desktop shell needs —
//! opening the real TUN device and installing/removing kill-switch firewall
//! rules — out of the (unprivileged) GUI process. This daemon runs as root,
//! listening on a Unix domain socket; the GUI connects to it and speaks the
//! [`ferrum_tunnel::helper_proto`] request/response protocol instead of
//! touching `/dev/net/tun` or shelling out to `nft` itself.
//!
//! ```text
//! ferrum-helper --socket /run/ferrum/helper.sock --group ferrum
//! ```
//!
//! The socket is `chown`'d to `--group` and `chmod 0660` — the standard Unix
//! daemon-socket trust boundary (the same model as `docker.sock`'s `docker`
//! group) — and the daemon **refuses to start** if the group doesn't exist.
//! Each connection's peer credentials are also checked (root, group members,
//! or an `--allow-uid`), and allowed callers are rate-limited (SEC-005). See
//! `packaging/systemd/ferrum-helper.service` for the systemd unit and
//! `apps/desktop/README.md` for the one-time setup steps.
//!
//! **Linux/Unix only for now** (Phase 5 scope): a Windows helper would need a
//! service host + named-pipe transport, which isn't built yet (the wire
//! protocol is deliberately transport-agnostic so it can plug in later — see
//! `ferrum_tunnel::helper_proto`'s module docs). On non-Unix this binary just
//! reports that it isn't supported, so the crate still builds everywhere.

use clap::Parser;

/// `ferrum-helper` CLI arguments. Kept platform-independent (`clap` has no
/// Unix-only bits) so the crate builds — inertly — on every target; the
/// actual daemon logic is `cfg(unix)`-gated in the `unix` module.
#[derive(Parser)]
#[command(
    name = "ferrum-helper",
    version,
    about = "Ferrum privileged helper daemon (Phase 5)"
)]
struct Cli {
    /// Unix domain socket path to listen on.
    #[arg(long, default_value = "/run/ferrum/helper.sock")]
    socket: String,
    /// Group the socket is `chown`'d to (mode 0660); its members may use the
    /// helper. Must exist — the daemon refuses to start otherwise.
    #[arg(long, default_value = "ferrum")]
    group: String,
    /// Additionally allow this uid regardless of group membership
    /// (repeatable). Root is always allowed.
    #[arg(long = "allow-uid", value_name = "UID")]
    allow_uids: Vec<u32>,
}

#[cfg(unix)]
mod unix;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    #[cfg(unix)]
    {
        unix::init_tracing();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(unix::run(&cli.socket, &cli.group, &cli.allow_uids))
    }

    #[cfg(not(unix))]
    {
        let _ = cli;
        anyhow::bail!(
            "ferrum-helper is Linux/Unix-only for now; a Windows helper service \
             is a documented follow-up (see STATUS.md)"
        )
    }
}
