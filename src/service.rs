// SPDX-License-Identifier: Apache-2.0
//! User-level systemd lifecycle integration for the operator-preview directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::ServiceAction;

const UNIT_NAME: &str = "iicp-directory-rs.service";

struct Unit {
    path: PathBuf,
    content: String,
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is required for a user-level service".to_string())
}

fn unit_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".config/systemd/user").join(UNIT_NAME))
}

fn systemd_quote(path: &Path) -> String {
    let escaped = path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn render_unit(
    executable: &Path,
    env_file: &Path,
    notify: bool,
    watchdog_sec: Option<u64>,
) -> Result<Unit, String> {
    if !env_file.is_absolute() {
        return Err("--env-file must be an absolute path".into());
    }
    if watchdog_sec.is_some() && !notify {
        return Err("--watchdog-sec requires --notify".into());
    }
    if notify && !cfg!(all(target_os = "linux", feature = "systemd-notify")) {
        return Err("--notify requires a Linux build with the systemd-notify feature".into());
    }
    let service_type = if notify {
        "notify\nNotifyAccess=main"
    } else {
        "simple"
    };
    let watchdog = watchdog_sec
        .map(|seconds| format!("\nWatchdogSec={seconds}"))
        .unwrap_or_default();
    let notify_env = if notify {
        "\nEnvironment=IICP_SYSTEMD_NOTIFY=1"
    } else {
        ""
    };
    let content = format!(
        "[Unit]\nDescription=IICP Rust directory operator preview\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=600\nStartLimitBurst=5\n\n[Service]\nType={service_type}{watchdog}\nExecStart={}\nEnvironmentFile={}{}\nRestart=always\nRestartSec=30\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\n[Install]\nWantedBy=default.target\n",
        systemd_quote(executable),
        systemd_quote(env_file),
        notify_env
    );
    Ok(Unit {
        path: unit_path()?,
        content,
    })
}

fn current_executable() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|error| format!("cannot resolve current executable: {error}"))
}

fn write_unit(unit: &Unit) -> Result<(), String> {
    if let Some(parent) = unit.path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(&unit.path, &unit.content).map_err(|error| error.to_string())
}

fn stable_executable() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".local/bin/iicp-directory-rs"))
}

fn manager(args: &[&str], dry_run: bool, tolerate_failure: bool) -> Result<(), String> {
    println!("manager: systemctl {}", args.join(" "));
    if dry_run {
        return Ok(());
    }
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|error| format!("systemctl: {error}"))?;
    if !status.success() && !tolerate_failure {
        return Err(format!("systemctl {} failed with {status}", args.join(" ")));
    }
    Ok(())
}

fn show(dry_run: bool) -> Result<(), String> {
    manager(
        &[
            "--user",
            "show",
            UNIT_NAME,
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "UnitFileState",
            "-p",
            "Restart",
            "-p",
            "RestartUSec",
            "-p",
            "Type",
            "-p",
            "WatchdogUSec",
            "-p",
            "NotifyAccess",
        ],
        dry_run,
        false,
    )
}

pub(crate) fn run(action: ServiceAction) -> Result<(), String> {
    match action {
        ServiceAction::Install {
            env_file,
            no_start,
            notify,
            watchdog_sec,
            dry_run,
        } => {
            if !dry_run && !env_file.is_file() {
                return Err(format!(
                    "environment file does not exist: {}",
                    env_file.display()
                ));
            }
            let current = current_executable()?;
            let stable = stable_executable()?;
            let unit = render_unit(&stable, &env_file, notify, watchdog_sec)?;
            if dry_run {
                println!(
                    "# managed executable: {} -> {}",
                    stable.display(),
                    current.display()
                );
                println!("# path: {}\n{}", unit.path.display(), unit.content);
            } else {
                if stable.exists() && !stable.is_symlink() {
                    return Err(format!(
                        "managed executable exists but is not a symlink: {}",
                        stable.display()
                    ));
                }
                if let Some(parent) = stable.parent() {
                    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
                }
                #[cfg(unix)]
                {
                    let replacement = stable.with_extension(format!("tmp-{}", std::process::id()));
                    let _ = fs::remove_file(&replacement);
                    std::os::unix::fs::symlink(&current, &replacement)
                        .map_err(|error| error.to_string())?;
                    fs::rename(&replacement, &stable).map_err(|error| error.to_string())?;
                }
                write_unit(&unit)?;
                println!("installed {}", unit.path.display());
            }
            manager(&["--user", "daemon-reload"], dry_run, false)?;
            manager(&["--user", "enable", UNIT_NAME], dry_run, false)?;
            if !no_start {
                manager(&["--user", "start", UNIT_NAME], dry_run, false)?;
            }
            show(dry_run)?;
            println!("boot persistence requires user lingering; inspect with: loginctl show-user \"$USER\" -p Linger");
            println!(
                "native watchdog: {}",
                if watchdog_sec.is_some() {
                    "enabled with operator-supplied measured interval"
                } else {
                    "disabled"
                }
            );
        }
        ServiceAction::Status => show(false)?,
        ServiceAction::Restart => manager(&["--user", "restart", UNIT_NAME], false, false)?,
        ServiceAction::Uninstall { dry_run } => {
            manager(&["--user", "disable", "--now", UNIT_NAME], dry_run, true)?;
            let path = unit_path()?;
            if dry_run {
                println!("remove: {}", path.display());
            } else if path.exists() {
                fs::remove_file(path).map_err(|error| error.to_string())?;
            }
            manager(&["--user", "daemon-reload"], dry_run, false)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_service_keeps_watchdog_disabled() {
        let unit = render_unit(
            Path::new("/usr/local/bin/iicp-directory-rs"),
            Path::new("/etc/iicp/directory.env"),
            false,
            None,
        )
        .unwrap();
        assert!(unit.content.contains("Type=simple"));
        assert!(unit.content.contains("Restart=always"));
        assert!(!unit.content.contains("WatchdogSec="));
        assert!(!unit.content.contains("IICP_SYSTEMD_NOTIFY"));
    }

    #[cfg(all(target_os = "linux", feature = "systemd-notify"))]
    #[test]
    fn notify_service_never_guesses_watchdog_interval() {
        let unit = render_unit(
            Path::new("/usr/local/bin/iicp-directory-rs"),
            Path::new("/etc/iicp/directory.env"),
            true,
            None,
        )
        .unwrap();
        assert!(unit.content.contains("Type=notify"));
        assert!(!unit.content.contains("WatchdogSec="));
    }

    #[test]
    fn watchdog_requires_notify() {
        assert!(render_unit(
            Path::new("/usr/local/bin/iicp-directory-rs"),
            Path::new("/etc/iicp/directory.env"),
            false,
            Some(180),
        )
        .is_err());
    }

    #[test]
    fn generated_unit_write_is_idempotent() {
        let root = std::env::temp_dir().join(format!("iicp-service-{}", uuid::Uuid::new_v4()));
        let unit = Unit {
            path: root.join("iicp-directory-rs.service"),
            content: "[Service]\nRestart=always\n".into(),
        };
        write_unit(&unit).unwrap();
        let first = fs::read(&unit.path).unwrap();
        write_unit(&unit).unwrap();
        assert_eq!(fs::read(&unit.path).unwrap(), first);
        fs::remove_dir_all(root).unwrap();
    }
}
