use std::error::Error;
use std::result::Result;

use crate::AgentTask;
use crate::mythic_success;

use super::{SshArgs, SshSession};

pub fn ssh_remove(
    sess: &SshSession,
    task: &AgentTask,
    args: &SshArgs,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let path_name = args.rm.as_ref().unwrap();
    let stat = sess.sftp_stat(path_name)?;
    sess.sftp_remove(path_name, stat.is_dir)?;

    let mut output = mythic_success!(task.id, format!("Removed: '{}'", path_name));
    let output = output.as_object_mut().unwrap();
    output.insert(
        "artifacts".to_string(),
        serde_json::json!([
            {
                "base_artifact": "Remote FileRemove",
                "artifact": format!("ssh {}@{} -rm {}", args.credentials.account, args.host, path_name),
            }
        ]),
    );

    Ok(serde_json::to_value(output)?)
}
