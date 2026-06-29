//! `ferrum-helper` — the privileged helper service (Phase 5 — Windows, FR5).
//!
//! A long-lived Windows service that owns the elevated parts of the data plane
//! (the wintun adapter and the WFP kill-switch) so the desktop GUI can run
//! unprivileged and drive it over a [named pipe](app_lib::ipc). See
//! [`app_lib::service`] for the pipe protocol and session handling.
//!
//! Subcommands:
//! * `install` — register the service with the SCM (pointed at this exe, `run`).
//! * `uninstall` — stop + delete the service.
//! * `run` — the SCM entry point (started by the Service Control Manager).
//! * `run-console` — run the pipe server in the foreground (for testing under an
//!   elevated console without installing the service); Ctrl-C stops it.
//!
//! On non-Windows this binary only prints that the helper service is
//! Windows-only — the Unix desktop brings the data plane up in-process.

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows_impl::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "ferrum-helper is the Windows privileged-helper service; on Unix the \
         desktop runs the data plane in-process (no helper needed)."
    );
    std::process::exit(1);
}

#[cfg(windows)]
mod windows_impl {
    use std::ffi::OsString;
    use std::time::Duration;

    use tokio::sync::watch;
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    /// Service name (SCM key) and display name.
    const SERVICE_NAME: &str = "ferrum-helper";
    const DISPLAY_NAME: &str = "Ferrum VPN Helper";
    /// Services run as their own process.
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        match std::env::args().nth(1).as_deref() {
            Some("install") => install(),
            Some("uninstall") => uninstall(),
            Some("run-console") => run_console(),
            // `run` (or no arg, the way the SCM launches us) hands control to the
            // SCM dispatcher, which calls `service_main`.
            Some("run") | None => {
                service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
                Ok(())
            }
            Some(other) => {
                eprintln!(
                    "unknown subcommand '{other}' (expected install|uninstall|run|run-console)"
                );
                std::process::exit(2);
            }
        }
    }

    /// Register the service with the SCM, pointing it at this executable's `run`.
    fn install() -> Result<(), Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let exe = std::env::current_exe()?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec![OsString::from("run")],
            dependencies: vec![],
            account_name: None, // None == LocalSystem (the elevation we need)
            account_password: None,
        };
        let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
        service.set_description(
            "Owns the Ferrum VPN data plane (wintun adapter + WFP kill-switch) so the \
             desktop app can run unprivileged.",
        )?;
        println!("installed service '{SERVICE_NAME}' (start it with: sc start {SERVICE_NAME})");
        Ok(())
    }

    /// Stop (if running) and delete the service.
    fn uninstall() -> Result<(), Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )?;
        // Best-effort stop before delete; ignore "not running".
        let _ = service.stop();
        service.delete()?;
        println!("uninstalled service '{SERVICE_NAME}'");
        Ok(())
    }

    /// Run the pipe server in the foreground (elevated console), Ctrl-C to stop.
    /// Lets a developer exercise the service without installing it under the SCM.
    fn run_console() -> Result<(), Box<dyn std::error::Error>> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let (stop_tx, stop_rx) = watch::channel(false);
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = stop_tx.send(true);
            });
            println!(
                "ferrum-helper running on {} (Ctrl-C to stop)",
                app_lib::ipc::PIPE_NAME
            );
            app_lib::service::serve(stop_rx).await
        })?;
        Ok(())
    }

    define_windows_service!(ffi_service_main, service_main);

    /// SCM entry point. Reports status to the SCM and runs the pipe server until a
    /// Stop control arrives.
    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run_service() {
            log::error!("ferrum-helper service exited with error: {e}");
        }
    }

    fn run_service() -> Result<(), Box<dyn std::error::Error>> {
        // `stop_tx` is flipped from the SCM control handler; `serve` watches it.
        let (stop_tx, stop_rx) = watch::channel(false);

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = stop_tx.send(true);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        let set_state = |state: ServiceState, controls: ServiceControlAccept| {
            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: state,
                controls_accepted: controls,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
        };

        set_state(ServiceState::Running, ServiceControlAccept::STOP)?;

        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(app_lib::service::serve(stop_rx));

        set_state(ServiceState::Stopped, ServiceControlAccept::empty())?;
        result.map_err(Into::into)
    }
}
