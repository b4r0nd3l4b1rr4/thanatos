use std::error::Error;
use std::result::Result;

use crate::AgentTask;
use crate::mythic_success;

use super::{SshArgs, SshSession};

pub fn ssh_cat(
    sess: &SshSession,
    task: &AgentTask,
    args: &SshArgs,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let file_name = args.cat.as_ref().unwrap();
    let file_contents = sess.sftp_read(file_name)?;

    let mut output = mythic_success!(task.id, std::str::from_utf8(&file_contents)?);
    let output = output.as_object_mut().unwrap();
    output.insert(
        "artifacts".to_string(),
        serde_json::json!([
            {
                "base_artifact": "Remote FileOpen",
                "artifact": format!("ssh {}@{} -cat {}", args.credentials.account, args.host, file_name)
            }
        ]),
    );

    Ok(serde_json::to_value(output)?)
}
