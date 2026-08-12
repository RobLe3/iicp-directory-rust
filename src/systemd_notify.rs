// SPDX-License-Identifier: Apache-2.0
//! Thin, opt-in systemd consumer of the platform-neutral runtime-health model.

#[cfg(target_os = "linux")]
use crate::runtime_health::RuntimeHealth;
#[cfg(any(test, target_os = "linux"))]
use crate::runtime_health::{Lifecycle, Liveness, Readiness};
#[cfg(target_os = "linux")]
use sd_notify::NotifyState;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
const OPT_IN_ENV: &str = "IICP_SYSTEMD_NOTIFY";

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NotificationDecision {
    ready: bool,
    watchdog: bool,
}

#[cfg(any(test, target_os = "linux"))]
fn decision(
    lifecycle: Lifecycle,
    liveness: Liveness,
    _readiness: Readiness,
    ready_sent: bool,
    watchdog_configured: bool,
) -> NotificationDecision {
    let live_running = lifecycle == Lifecycle::Running && liveness == Liveness::Live;
    NotificationDecision {
        ready: live_running && !ready_sent,
        watchdog: live_running && watchdog_configured,
    }
}

/// Start the native notifier only after explicit opt-in and systemd socket discovery.
///
/// The pulse timer is a consumer, never the health source. A stalled Tokio runtime
/// cannot keep this task alive, and a stale health snapshot withholds the pulse.
#[cfg(target_os = "linux")]
pub fn spawn_if_enabled(health: RuntimeHealth) -> Option<tokio::task::JoinHandle<()>> {
    if std::env::var(OPT_IN_ENV).as_deref() != Ok("1")
        || std::env::var_os("NOTIFY_SOCKET").is_none()
    {
        return None;
    }
    let watchdog = sd_notify::watchdog_enabled();
    let cadence = watchdog
        .map(|duration| duration.div_f32(2.0))
        .unwrap_or(Duration::from_millis(500))
        .max(Duration::from_millis(100));
    Some(tokio::spawn(async move {
        let mut ready_sent = false;
        let mut interval = tokio::time::interval(cadence);
        loop {
            interval.tick().await;
            let snapshot = health.snapshot();
            let action = decision(
                snapshot.lifecycle,
                snapshot.liveness,
                snapshot.readiness,
                ready_sent,
                watchdog.is_some(),
            );
            let status = format!(
                "liveness={:?}; readiness={:?}",
                snapshot.liveness, snapshot.readiness
            )
            .to_lowercase();
            if action.ready {
                let _ = sd_notify::notify(&[NotifyState::Ready, NotifyState::Status(&status)]);
                ready_sent = true;
            } else {
                let _ = sd_notify::notify(&[NotifyState::Status(&status)]);
            }
            if action.watchdog {
                let _ = sd_notify::notify(&[NotifyState::Watchdog]);
            }
        }
    }))
}

/// Report an orderly stop; the service manager remains the restart authority.
#[cfg(target_os = "linux")]
pub fn notify_stopping() {
    if std::env::var(OPT_IN_ENV).as_deref() == Ok("1") {
        let _ = sd_notify::notify(&[NotifyState::Stopping, NotifyState::Status("Stopping")]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use tokio::sync::Mutex;

    // Native notification tests mutate process-global systemd environment.
    // Serialize them so parallel test execution cannot redirect or remove a
    // peer test's NOTIFY_SOCKET while its notifier task is still running.
    #[cfg(target_os = "linux")]
    static NOTIFY_ENV_LOCK: Mutex<()> = Mutex::const_new(());

    #[test]
    fn ready_and_watchdog_require_meaningful_live_runtime_progress() {
        let action = decision(
            Lifecycle::Running,
            Liveness::Live,
            Readiness::Degraded,
            false,
            true,
        );
        assert_eq!(
            action,
            NotificationDecision {
                ready: true,
                watchdog: true
            }
        );
    }

    #[test]
    fn stale_runtime_withholds_watchdog_even_when_process_and_timer_exist() {
        let action = decision(
            Lifecycle::Running,
            Liveness::NotLive,
            Readiness::NotReady,
            true,
            true,
        );
        assert_eq!(
            action,
            NotificationDecision {
                ready: false,
                watchdog: false
            }
        );
    }

    #[test]
    fn external_degradation_does_not_withhold_local_liveness_pulse() {
        let action = decision(
            Lifecycle::Running,
            Liveness::Live,
            Readiness::Degraded,
            true,
            true,
        );
        assert_eq!(
            action,
            NotificationDecision {
                ready: false,
                watchdog: true
            }
        );
    }

    #[cfg(all(target_os = "linux", feature = "runtime-health-fault-injection"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_socket_pulses_live_runtime_then_withholds_after_stall() {
        use crate::runtime_health::{RuntimeHealth, RuntimeHealthFault};
        use std::os::unix::net::UnixDatagram;

        let _env_guard = NOTIFY_ENV_LOCK.lock().await;

        let socket_path = std::env::temp_dir().join(format!(
            "iicp-notify-{}-{}.sock",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let socket = UnixDatagram::bind(&socket_path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        std::env::set_var(OPT_IN_ENV, "1");
        std::env::set_var("NOTIFY_SOCKET", &socket_path);
        std::env::set_var("WATCHDOG_USEC", "200000");
        std::env::set_var("WATCHDOG_PID", std::process::id().to_string());

        let health = RuntimeHealth::new(false);
        health.mark_running();
        health.advance_runtime();
        let handle = spawn_if_enabled(health.clone()).expect("notifier enabled");

        let mut initial = String::new();
        for _ in 0..4 {
            let mut buf = [0_u8; 512];
            if let Ok(size) = socket.recv(&mut buf) {
                initial.push_str(&String::from_utf8_lossy(&buf[..size]));
            }
            if initial.contains("READY=1") && initial.contains("WATCHDOG=1") {
                break;
            }
        }
        assert!(initial.contains("READY=1"));
        assert!(initial.contains("WATCHDOG=1"));

        socket.set_nonblocking(true).unwrap();
        let mut drain = [0_u8; 512];
        while socket.recv(&mut drain).is_ok() {}
        health.inject_fault(RuntimeHealthFault::RuntimeProgressStale);
        tokio::time::sleep(Duration::from_millis(150)).await;
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut after_stall = String::new();
        for _ in 0..2 {
            let mut buf = [0_u8; 512];
            if let Ok(size) = socket.recv(&mut buf) {
                after_stall.push_str(&String::from_utf8_lossy(&buf[..size]));
            }
        }
        assert!(after_stall.contains("liveness=notlive"));
        assert!(!after_stall.contains("WATCHDOG=1"));

        handle.abort();
        std::env::remove_var(OPT_IN_ENV);
        std::env::remove_var("NOTIFY_SOCKET");
        std::env::remove_var("WATCHDOG_USEC");
        std::env::remove_var("WATCHDOG_PID");
        let _ = std::fs::remove_file(socket_path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_socket_reports_orderly_stopping() {
        use std::os::unix::net::UnixDatagram;

        let _env_guard = NOTIFY_ENV_LOCK.blocking_lock();

        let socket_path = std::env::temp_dir().join(format!(
            "iicp-notify-stop-{}-{}.sock",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let socket = UnixDatagram::bind(&socket_path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        std::env::set_var(OPT_IN_ENV, "1");
        std::env::set_var("NOTIFY_SOCKET", &socket_path);

        notify_stopping();

        let mut buf = [0_u8; 512];
        let size = socket.recv(&mut buf).unwrap();
        let notification = String::from_utf8_lossy(&buf[..size]);
        assert!(notification.contains("STOPPING=1"));
        assert!(notification.contains("STATUS=Stopping"));

        std::env::remove_var(OPT_IN_ENV);
        std::env::remove_var("NOTIFY_SOCKET");
        let _ = std::fs::remove_file(socket_path);
    }
}
