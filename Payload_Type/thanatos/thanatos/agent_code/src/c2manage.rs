use crate::AgentTask;
use crate::{mythic_success, payloadvars};
use serde::Deserialize;

#[derive(Deserialize)]
struct KilldateArgs {
    action: String,
    date: Option<String>,
}

/// Show current C2 configuration
pub fn c2info(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let callback_host = option_env!("callback_host").unwrap_or("unknown");
    let callback_port = option_env!("callback_port").unwrap_or("unknown");
    let callback_interval = payloadvars::callback_interval();
    let callback_jitter = payloadvars::callback_jitter();
    let killdate = payloadvars::killdate();

    let info = format!(
        "C2 Configuration:\n\
        Callback Host: {}\n\
        Callback Port: {}\n\
        Sleep Interval: {} seconds\n\
        Jitter: {}%\n\
        Kill Date: {}",
        callback_host, callback_port, callback_interval, callback_jitter, killdate
    );

    Ok(mythic_success!(task.id, info))
}

/// Get or set the agent killdate
pub fn killdate(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: KilldateArgs = serde_json::from_str(&task.parameters)?;

    match args.action.as_str() {
        "get" => {
            let current_killdate = payloadvars::killdate();
            let result = format!("Current killdate: {}", current_killdate);
            Ok(mythic_success!(task.id, result))
        }
        "set" => {
            if let Some(_date) = args.date {
                // Note: Killdate is compiled into the binary at build time
                // Runtime modification is not supported without shared state
                let result = "Killdate is set at compile time and cannot be modified at runtime. \
                             To change the killdate, rebuild the payload with the new killdate value."
                    .to_string();
                Ok(mythic_success!(task.id, result))
            } else {
                let result = "Error: 'set' action requires a date parameter in YYYY-MM-DD format.".to_string();
                Ok(mythic_success!(task.id, result))
            }
        }
        _ => {
            let result = format!("Error: Unknown action '{}'. Use 'get' or 'set'.", args.action);
            Ok(mythic_success!(task.id, result))
        }
    }
}
