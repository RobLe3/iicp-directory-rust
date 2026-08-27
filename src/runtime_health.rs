// SPDX-License-Identifier: Apache-2.0
//! Local, implementation-level runtime health. This is not an IICP wire profile.

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const HEALTH_SCHEMA_VERSION: u8 = 1;
pub const RUNTIME_STALE_AFTER: Duration = Duration::from_secs(30);
pub const SUPERVISOR_STALE_AFTER: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Starting,
    Running,
    Stopping,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Liveness {
    Starting,
    Live,
    NotLive,
    Indeterminate,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Ready,
    Degraded,
    NotReady,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsystemState {
    Healthy,
    Degraded,
    Recovering,
    Unavailable,
    NotApplicable,
    Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    Starting,
    Stopping,
    RuntimeProgressStale,
    SupervisorProgressStale,
    ProviderUnavailable,
    NoCapacity,
    RoutingUnavailable,
    TunnelRecovering,
    DirectoryUnavailable,
    DnsUnavailable,
    InternetUnavailable,
    StateUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProgressSnapshot {
    pub sequence: u64,
    pub age_ms: u64,
    pub stale_after_ms: u64,
    pub required: bool,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProgressSet {
    pub runtime: ProgressSnapshot,
    pub supervisor: ProgressSnapshot,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HealthSnapshot {
    pub health_schema_version: u8,
    pub process_epoch: String,
    pub pid: u32,
    pub sequence: u64,
    pub emitted_at: String,
    pub lifecycle: Lifecycle,
    pub liveness: Liveness,
    pub readiness: Readiness,
    pub progress: ProgressSet,
    pub subsystems: BTreeMap<String, SubsystemState>,
    pub external_connectivity: BTreeMap<String, SubsystemState>,
    pub reason_codes: Vec<ReasonCode>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClassificationInput {
    pub lifecycle: Lifecycle,
    pub runtime_age_ms: u64,
    pub runtime_stale_after_ms: u64,
    pub supervisor_required: bool,
    pub supervisor_age_ms: u64,
    pub supervisor_stale_after_ms: u64,
    pub provider: SubsystemState,
    pub capacity_available: bool,
    pub routing: SubsystemState,
    pub directory: SubsystemState,
    pub dns: SubsystemState,
    pub internet: SubsystemState,
    pub tunnel: SubsystemState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClassificationOutput {
    pub liveness: Liveness,
    pub readiness: Readiness,
    pub reason_codes: Vec<ReasonCode>,
}

pub fn classify_input(i: &ClassificationInput) -> ClassificationOutput {
    let mut reasons = Vec::new();
    if i.lifecycle == Lifecycle::Starting {
        reasons.push(ReasonCode::Starting);
        return ClassificationOutput {
            liveness: Liveness::Starting,
            readiness: Readiness::NotReady,
            reason_codes: reasons,
        };
    }
    if i.runtime_age_ms > i.runtime_stale_after_ms {
        reasons.push(ReasonCode::RuntimeProgressStale);
        return ClassificationOutput {
            liveness: Liveness::NotLive,
            readiness: Readiness::NotReady,
            reason_codes: reasons,
        };
    }
    if i.supervisor_required && i.supervisor_age_ms > i.supervisor_stale_after_ms {
        reasons.push(ReasonCode::SupervisorProgressStale);
        return ClassificationOutput {
            liveness: Liveness::NotLive,
            readiness: Readiness::NotReady,
            reason_codes: reasons,
        };
    }
    if i.lifecycle == Lifecycle::Stopping {
        reasons.push(ReasonCode::Stopping);
        return ClassificationOutput {
            liveness: Liveness::Live,
            readiness: Readiness::NotReady,
            reason_codes: reasons,
        };
    }
    if i.provider == SubsystemState::Unavailable {
        reasons.push(ReasonCode::ProviderUnavailable);
    }
    if !i.capacity_available {
        reasons.push(ReasonCode::NoCapacity);
    }
    if i.routing == SubsystemState::Unavailable {
        reasons.push(ReasonCode::RoutingUnavailable);
    }
    if i.tunnel == SubsystemState::Recovering {
        reasons.push(ReasonCode::TunnelRecovering);
    }
    if i.directory == SubsystemState::Unavailable {
        reasons.push(ReasonCode::DirectoryUnavailable);
    }
    if i.dns == SubsystemState::Unavailable {
        reasons.push(ReasonCode::DnsUnavailable);
    }
    if i.internet == SubsystemState::Unavailable {
        reasons.push(ReasonCode::InternetUnavailable);
    }
    let not_ready = reasons.iter().any(|r| {
        matches!(
            r,
            ReasonCode::ProviderUnavailable
                | ReasonCode::NoCapacity
                | ReasonCode::RoutingUnavailable
        )
    });
    ClassificationOutput {
        liveness: Liveness::Live,
        readiness: if not_ready {
            Readiness::NotReady
        } else if reasons.is_empty() {
            Readiness::Ready
        } else {
            Readiness::Degraded
        },
        reason_codes: reasons,
    }
}

struct State {
    lifecycle: Lifecycle,
    runtime_sequence: u64,
    supervisor_sequence: u64,
    last_runtime: Instant,
    last_supervisor: Instant,
    supervisor_required: bool,
    capacity_available: bool,
    subsystems: BTreeMap<String, SubsystemState>,
    external: BTreeMap<String, SubsystemState>,
    snapshot_sequence: u64,
}
#[derive(Clone)]
pub struct RuntimeHealth {
    epoch: String,
    state: Arc<Mutex<State>>,
}

#[cfg(feature = "runtime-health-fault-injection")]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeHealthFault {
    RuntimeProgressStale,
    SupervisorProgressStale,
    DirectoryUnavailable,
    DnsUnavailable,
    InternetUnavailable,
    TunnelRecovering,
    ProviderUnavailable,
    Clear,
}

impl RuntimeHealth {
    pub fn new(supervisor_required: bool) -> Self {
        let now = Instant::now();
        let mut subsystems = BTreeMap::new();
        for name in ["provider", "routing", "tunnel"] {
            subsystems.insert(name.into(), SubsystemState::Unknown);
        }
        let mut external = BTreeMap::new();
        for name in ["directory", "dns", "internet"] {
            external.insert(name.into(), SubsystemState::Unknown);
        }
        Self {
            epoch: uuid::Uuid::new_v4().to_string(),
            state: Arc::new(Mutex::new(State {
                lifecycle: Lifecycle::Starting,
                runtime_sequence: 0,
                supervisor_sequence: 0,
                last_runtime: now,
                last_supervisor: now,
                supervisor_required,
                capacity_available: false,
                subsystems,
                external,
                snapshot_sequence: 0,
            })),
        }
    }
    pub fn mark_running(&self) {
        let mut s = self.state.lock().unwrap();
        s.lifecycle = Lifecycle::Running;
        s.capacity_available = true;
        s.subsystems
            .insert("provider".into(), SubsystemState::Healthy);
        s.subsystems
            .insert("routing".into(), SubsystemState::Healthy);
    }
    pub fn mark_stopping(&self) {
        self.state.lock().unwrap().lifecycle = Lifecycle::Stopping;
    }
    pub fn advance_runtime(&self) {
        let mut s = self.state.lock().unwrap();
        s.runtime_sequence += 1;
        s.last_runtime = Instant::now();
    }
    pub fn advance_supervisor(&self) {
        let mut s = self.state.lock().unwrap();
        s.supervisor_sequence += 1;
        s.last_supervisor = Instant::now();
    }
    #[allow(dead_code)]
    pub fn set_supervisor_required(&self, required: bool) {
        self.state.lock().unwrap().supervisor_required = required;
    }
    #[allow(dead_code)]
    pub fn set_subsystem(&self, name: &str, value: SubsystemState) {
        self.state
            .lock()
            .unwrap()
            .subsystems
            .insert(name.into(), value);
    }
    #[allow(dead_code)]
    pub fn set_external(&self, name: &str, value: SubsystemState) {
        self.state
            .lock()
            .unwrap()
            .external
            .insert(name.into(), value);
    }
    /// Deterministic development/test hook for supervision evidence.
    ///
    /// This API exists only in explicit fault-injection builds and has no CLI,
    /// HTTP or environment-variable activation path.
    #[cfg(feature = "runtime-health-fault-injection")]
    #[allow(dead_code)]
    pub fn inject_fault(&self, fault: RuntimeHealthFault) {
        let now = Instant::now();
        let mut s = self.state.lock().unwrap();
        match fault {
            RuntimeHealthFault::RuntimeProgressStale => {
                s.last_runtime = now - RUNTIME_STALE_AFTER - Duration::from_millis(1);
            }
            RuntimeHealthFault::SupervisorProgressStale => {
                s.supervisor_required = true;
                s.last_supervisor = now - SUPERVISOR_STALE_AFTER - Duration::from_millis(1);
            }
            RuntimeHealthFault::DirectoryUnavailable => {
                s.external
                    .insert("directory".into(), SubsystemState::Unavailable);
            }
            RuntimeHealthFault::DnsUnavailable => {
                s.external.insert("dns".into(), SubsystemState::Unavailable);
            }
            RuntimeHealthFault::InternetUnavailable => {
                s.external
                    .insert("internet".into(), SubsystemState::Unavailable);
            }
            RuntimeHealthFault::TunnelRecovering => {
                s.subsystems
                    .insert("tunnel".into(), SubsystemState::Recovering);
            }
            RuntimeHealthFault::ProviderUnavailable => {
                s.subsystems
                    .insert("provider".into(), SubsystemState::Unavailable);
                s.capacity_available = false;
            }
            RuntimeHealthFault::Clear => {
                s.last_runtime = now;
                s.last_supervisor = now;
                s.capacity_available = true;
                s.subsystems
                    .insert("provider".into(), SubsystemState::Healthy);
                s.subsystems
                    .insert("routing".into(), SubsystemState::Healthy);
                s.subsystems
                    .insert("tunnel".into(), SubsystemState::Healthy);
                for name in ["directory", "dns", "internet"] {
                    s.external.insert(name.into(), SubsystemState::Healthy);
                }
            }
        }
    }
    pub fn snapshot(&self) -> HealthSnapshot {
        let now = Instant::now();
        let mut s = self.state.lock().unwrap();
        s.snapshot_sequence += 1;
        let runtime_age = now.duration_since(s.last_runtime);
        let supervisor_age = now.duration_since(s.last_supervisor);
        let result = classify_input(&ClassificationInput {
            lifecycle: s.lifecycle,
            runtime_age_ms: ms(runtime_age),
            runtime_stale_after_ms: ms(RUNTIME_STALE_AFTER),
            supervisor_required: s.supervisor_required,
            supervisor_age_ms: ms(supervisor_age),
            supervisor_stale_after_ms: ms(SUPERVISOR_STALE_AFTER),
            provider: *s
                .subsystems
                .get("provider")
                .unwrap_or(&SubsystemState::Unknown),
            capacity_available: s.capacity_available,
            routing: *s
                .subsystems
                .get("routing")
                .unwrap_or(&SubsystemState::Unknown),
            directory: *s
                .external
                .get("directory")
                .unwrap_or(&SubsystemState::Unknown),
            dns: *s.external.get("dns").unwrap_or(&SubsystemState::Unknown),
            internet: *s
                .external
                .get("internet")
                .unwrap_or(&SubsystemState::Unknown),
            tunnel: *s
                .subsystems
                .get("tunnel")
                .unwrap_or(&SubsystemState::Unknown),
        });
        HealthSnapshot {
            health_schema_version: HEALTH_SCHEMA_VERSION,
            process_epoch: self.epoch.clone(),
            pid: std::process::id(),
            sequence: s.snapshot_sequence,
            emitted_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            lifecycle: s.lifecycle,
            liveness: result.liveness,
            readiness: result.readiness,
            progress: ProgressSet {
                runtime: ProgressSnapshot {
                    sequence: s.runtime_sequence,
                    age_ms: ms(runtime_age),
                    stale_after_ms: ms(RUNTIME_STALE_AFTER),
                    required: true,
                },
                supervisor: ProgressSnapshot {
                    sequence: s.supervisor_sequence,
                    age_ms: ms(supervisor_age),
                    stale_after_ms: ms(SUPERVISOR_STALE_AFTER),
                    required: s.supervisor_required,
                },
            },
            subsystems: s.subsystems.clone(),
            external_connectivity: s.external.clone(),
            reason_codes: result.reason_codes,
        }
    }
}
fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn write_atomic_with(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let create_parent = !parent.exists();
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        if create_parent {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut file = opts.open(&tmp)?;
        write(&mut file)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn write_snapshot_atomic(path: &Path, snapshot: &HealthSnapshot) -> std::io::Result<()> {
    write_atomic_with(path, |file| {
        serde_json::to_writer_pretty(&mut *file, snapshot)?;
        file.write_all(b"\n")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    #[test]
    fn shared_scenarios_keep_directory_classification_in_parity() {
        #[derive(Deserialize)]
        struct Fixture {
            scenarios: Vec<Scenario>,
        }
        #[derive(Deserialize)]
        struct Scenario {
            input: ClassificationInput,
            expected: ClassificationOutput,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("../parity/runtime-health-v1.json"))
                .expect("shared runtime-health fixture");
        for scenario in fixture.scenarios {
            assert_eq!(classify_input(&scenario.input), scenario.expected);
        }
    }

    #[test]
    fn external_loss_does_not_kill_runtime() {
        let h = RuntimeHealth::new(false);
        h.mark_running();
        h.advance_runtime();
        h.set_external("directory", SubsystemState::Unavailable);
        let s = h.snapshot();
        assert_eq!(s.liveness, Liveness::Live);
        assert_eq!(s.readiness, Readiness::Degraded);
    }
    #[test]
    fn startup_is_explicit() {
        let s = RuntimeHealth::new(true).snapshot();
        assert_eq!(s.liveness, Liveness::Starting);
        assert_eq!(s.readiness, Readiness::NotReady);
    }
    #[test]
    fn atomic_snapshot_is_private() {
        let dir = std::env::temp_dir().join(format!("iicp-health-{}", uuid::Uuid::new_v4()));
        let p = dir.join("health.json");
        let h = RuntimeHealth::new(false);
        write_snapshot_atomic(&p, &h.snapshot()).unwrap();
        let _: HealthSnapshot = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    fn seeded_snapshot() -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
        let dir = std::env::temp_dir().join(format!("iicp-health-{}", uuid::Uuid::new_v4()));
        let path = dir.join("health.json");
        let health = RuntimeHealth::new(false);
        write_snapshot_atomic(&path, &health.snapshot()).unwrap();
        let verified = fs::read(&path).unwrap();
        (dir, path, verified)
    }

    #[test]
    fn atomic_snapshot_permission_denied_preserves_private_verified_state() {
        let (dir, path, verified) = seeded_snapshot();
        let error = write_atomic_with(&path, |_file| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&path).unwrap(), verified);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn atomic_snapshot_disk_full_preserves_last_verified_state() {
        let (dir, path, verified) = seeded_snapshot();
        let error = write_atomic_with(&path, |file| {
            file.write_all(b"{\"partial\":true")?;
            Err(std::io::Error::from_raw_os_error(28))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(28));
        assert_eq!(fs::read(&path).unwrap(), verified);
        assert!(!path
            .with_extension(format!("tmp-{}", std::process::id()))
            .exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn atomic_snapshot_interruption_rejects_partial_generation() {
        let (dir, path, verified) = seeded_snapshot();
        let error = write_atomic_with(&path, |file| {
            file.write_all(b"{\"partial\":true")?;
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(fs::read(&path).unwrap(), verified);
        assert!(!path
            .with_extension(format!("tmp-{}", std::process::id()))
            .exists());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn runtime_age_advances_monotonically() {
        let h = RuntimeHealth::new(false);
        let a = h.snapshot().progress.runtime.age_ms;
        thread::sleep(Duration::from_millis(2));
        let b = h.snapshot().progress.runtime.age_ms;
        assert!(b >= a);
    }

    #[cfg(feature = "runtime-health-fault-injection")]
    #[test]
    fn fault_injection_distinguishes_local_stalls_from_external_degradation() {
        let h = RuntimeHealth::new(true);
        h.mark_running();
        h.inject_fault(RuntimeHealthFault::DirectoryUnavailable);
        let degraded = h.snapshot();
        assert_eq!(degraded.liveness, Liveness::Live);
        assert_eq!(degraded.readiness, Readiness::Degraded);

        h.inject_fault(RuntimeHealthFault::RuntimeProgressStale);
        let stalled = h.snapshot();
        assert_eq!(stalled.liveness, Liveness::NotLive);
        assert_eq!(stalled.readiness, Readiness::NotReady);
        assert!(stalled
            .reason_codes
            .contains(&ReasonCode::RuntimeProgressStale));

        h.inject_fault(RuntimeHealthFault::Clear);
        assert_eq!(h.snapshot().liveness, Liveness::Live);
    }
}
