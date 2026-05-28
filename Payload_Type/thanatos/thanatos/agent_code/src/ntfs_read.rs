// ntfs_read — requires MFTool (Docker rebuild with /opt/kudaes/MFTool)
// Returns informative error until Docker image is rebuilt

use crate::{AgentTask, mythic_error};
use std::error::Error;
use std::sync::mpsc;

pub fn ntfs_read(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "ntfs_read requires MFTool. Rebuild Docker image to enable."))?;
    Ok(())
}
