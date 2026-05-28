// minifilter/sync_drop — requires Puzzle SyncProvider (Docker rebuild with /opt/kudaes/Puzzle)

use crate::{AgentTask, mythic_error};
use std::error::Error;
use std::sync::mpsc;

pub fn sync_drop(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "sync_drop requires Puzzle SyncProvider. Rebuild Docker image to enable."))?;
    Ok(())
}
