use crate::AgentTask;
use serde::Deserialize;
use std::error::Error;
use std::result::Result;
use std::sync::{mpsc, Arc};

pub mod agent;
pub mod spawn;

mod cat;
mod download;
mod exec;
mod ls;
mod rm;
mod upload;

/// Mythic credentials for authentication
#[derive(Default, Debug, Deserialize)]
pub struct Credentials {
    /// Account to authenticate as
    pub account: String,

    /// Comment in the Mythic credentials
    pub _comment: String,

    /// Credential for authentication
    pub credential: String,

    /// Realm this credential is from
    pub _realm: String,

    /// Credential type
    #[serde(alias = "type")]
    pub cred_type: String,
}

/// Arguments for the SSH command
#[derive(Default, Debug, Deserialize)]
pub struct SshArgs {
    /// Credentials used for the SSH connection
    pub credentials: Credentials,

    /// Option for whether or not to use the connected SSH agent
    pub agent: bool,

    /// Host to connect to
    pub host: String,

    /// Port to connect to
    pub port: u32,

    /// Command to execute for `ssh -exec`
    pub exec: Option<String>,

    /// File to read for `ssh -cat`
    pub cat: Option<String>,

    /// File to remove for `ssh -rm`
    pub rm: Option<String>,

    /// File to download for `ssh -download`
    pub download: Option<String>,

    /// File to list for `ssh -ls`
    pub list: Option<String>,

    /// File to upload for `ssh -upload`
    pub upload: Option<String>,

    /// File permissions for uploaded file for `ssh -upload`
    pub mode: Option<i32>,

    /// Path to upload the file to for `ssh -upload`/`ssh-spawn`
    pub upload_path: Option<String>,
}

/// Converts the `ssh-spawn` arguments to `ssh` arguments
impl From<self::spawn::SshSpawnArgs> for SshArgs {
    fn from(spawn_args: self::spawn::SshSpawnArgs) -> Self {
        Self {
            credentials: spawn_args.credentials,
            host: spawn_args.host,
            agent: spawn_args.agent,
            port: spawn_args.port,
            exec: Some(spawn_args.exec),
            download: Some(spawn_args.payload),
            ..Default::default()
        }
    }
}

/// Connected SSH session wrapper
pub struct SshSession {
    session: russh::client::Handle<SshHandler>,
}

struct SshHandler;

#[async_trait::async_trait]
impl russh::client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl SshSession {
    pub fn channel_exec(&self, cmd: &str) -> Result<(String, String, i32), Box<dyn Error>> {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let mut channel = self.session.channel_open_session().await?;
            channel.exec(true, cmd.as_bytes()).await?;

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut exit_status: i32 = 0;

            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { ref data } => {
                        stdout.extend_from_slice(data);
                    }
                    russh::ChannelMsg::ExtendedData { ref data, ext } => {
                        if ext == 1 {
                            stderr.extend_from_slice(data);
                        }
                    }
                    russh::ChannelMsg::ExitStatus { exit_status: s } => {
                        exit_status = s as i32;
                    }
                    _ => {}
                }
            }

            Ok((
                String::from_utf8_lossy(&stdout).to_string(),
                String::from_utf8_lossy(&stderr).to_string(),
                exit_status,
            ))
        })
    }

    pub fn sftp_read(&self, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let cmd = format!("cat '{}'", path.replace('\'', "'\\''"));
            let mut channel = self.session.channel_open_session().await?;
            channel.exec(true, cmd.as_bytes()).await?;

            let mut data = Vec::new();
            while let Some(msg) = channel.wait().await {
                if let russh::ChannelMsg::Data { ref data: d } = msg {
                    data.extend_from_slice(d);
                }
            }
            Ok(data)
        })
    }

    pub fn sftp_write(&self, path: &str, data: &[u8], mode: i32) -> Result<(), Box<dyn Error>> {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let cmd = format!(
                "cat > '{}' && chmod {:o} '{}'",
                path.replace('\'', "'\\''"),
                mode,
                path.replace('\'', "'\\''")
            );
            let mut channel = self.session.channel_open_session().await?;
            channel.exec(true, cmd.as_bytes()).await?;
            channel.data(&data[..]).await?;
            channel.eof().await?;

            while let Some(msg) = channel.wait().await {
                if let russh::ChannelMsg::ExitStatus { exit_status } = msg {
                    if exit_status != 0 {
                        return Err(format!("Remote write failed with status {}", exit_status).into());
                    }
                }
            }
            Ok(())
        })
    }

    pub fn sftp_stat(&self, path: &str) -> Result<RemoteFileStat, Box<dyn Error>> {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let cmd = format!(
                "stat -c '%F %s %U %G %a %X %Y' '{}'",
                path.replace('\'', "'\\''")
            );
            let mut channel = self.session.channel_open_session().await?;
            channel.exec(true, cmd.as_bytes()).await?;

            let mut output = Vec::new();
            while let Some(msg) = channel.wait().await {
                if let russh::ChannelMsg::Data { ref data } = msg {
                    output.extend_from_slice(data);
                }
            }

            let line = String::from_utf8_lossy(&output);
            let line = line.trim();
            let parts: Vec<&str> = line.splitn(7, ' ').collect();
            if parts.len() < 7 {
                return Err(format!("Failed to stat '{}'", path).into());
            }

            Ok(RemoteFileStat {
                is_dir: parts[0] == "directory",
                size: parts[1].parse().unwrap_or(0),
                uid: 0,
                gid: 0,
                perm: u32::from_str_radix(parts[4], 8).unwrap_or(0o644),
                atime: parts[5].parse().unwrap_or(0),
                mtime: parts[6].parse().unwrap_or(0),
            })
        })
    }

    pub fn sftp_readdir(&self, path: &str) -> Result<Vec<(String, RemoteFileStat)>, Box<dyn Error>> {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let cmd = format!(
                "find '{}' -maxdepth 1 -printf '%y %s %U %G %m %A@ %T@ %p\\n'",
                path.replace('\'', "'\\''")
            );
            let mut channel = self.session.channel_open_session().await?;
            channel.exec(true, cmd.as_bytes()).await?;

            let mut output = Vec::new();
            while let Some(msg) = channel.wait().await {
                if let russh::ChannelMsg::Data { ref data } = msg {
                    output.extend_from_slice(data);
                }
            }

            let text = String::from_utf8_lossy(&output);
            let mut entries = Vec::new();
            for line in text.lines().skip(1) {
                let parts: Vec<&str> = line.splitn(8, ' ').collect();
                if parts.len() < 8 {
                    continue;
                }
                let stat = RemoteFileStat {
                    is_dir: parts[0] == "d",
                    size: parts[1].parse().unwrap_or(0),
                    uid: parts[2].parse().unwrap_or(0),
                    gid: parts[3].parse().unwrap_or(0),
                    perm: u32::from_str_radix(parts[4], 8).unwrap_or(0o644),
                    atime: parts[5].split('.').next().unwrap_or("0").parse().unwrap_or(0),
                    mtime: parts[6].split('.').next().unwrap_or("0").parse().unwrap_or(0),
                };
                entries.push((parts[7].to_string(), stat));
            }
            Ok(entries)
        })
    }

    pub fn sftp_remove(&self, path: &str, is_dir: bool) -> Result<(), Box<dyn Error>> {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let cmd = if is_dir {
                format!("rmdir '{}'", path.replace('\'', "'\\''"))
            } else {
                format!("rm -f '{}'", path.replace('\'', "'\\''"))
            };
            let mut channel = self.session.channel_open_session().await?;
            channel.exec(true, cmd.as_bytes()).await?;

            while let Some(msg) = channel.wait().await {
                if let russh::ChannelMsg::ExitStatus { exit_status } = msg {
                    if exit_status != 0 {
                        return Err(format!("Failed to remove '{}'", path).into());
                    }
                }
            }
            Ok(())
        })
    }
}

pub struct RemoteFileStat {
    pub is_dir: bool,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub perm: u32,
    pub atime: u64,
    pub mtime: u64,
}

/// Authenticates to a machine using ssh
pub fn ssh_authenticate(args: &SshArgs) -> Result<SshSession, Box<dyn Error>> {
    let rt = tokio::runtime::Handle::current();
    rt.block_on(async {
        let config = Arc::new(russh::client::Config::default());
        let handler = SshHandler;
        let addr = format!("{}:{}", args.host, args.port);
        let mut session = russh::client::connect(config, &*addr, handler).await?;

        if args.agent {
            let mut agent = russh_keys::agent::client::AgentClient::connect_env().await?;
            let identities = agent.request_identities().await?;
            let mut authenticated = false;
            for key in identities {
                if session
                    .authenticate_publickey(&args.credentials.account, Arc::new(key))
                    .await?
                {
                    authenticated = true;
                    break;
                }
            }
            if !authenticated {
                return Err("Could not authenticate with any stored ssh agent identities".into());
            }
        } else {
            match args.credentials.cred_type.as_str() {
                "plaintext" => {
                    if !session
                        .authenticate_password(&args.credentials.account, &args.credentials.credential)
                        .await?
                    {
                        return Err("Password authentication failed".into());
                    }
                }
                "key" => {
                    let key = russh_keys::decode_secret_key(&args.credentials.credential, None)?;
                    if !session
                        .authenticate_publickey(&args.credentials.account, Arc::new(key))
                        .await?
                    {
                        return Err("Key authentication failed".into());
                    }
                }
                _ => return Err("Invalid auth type".into()),
            }
        }

        Ok(SshSession { session })
    })
}

/// Run the ssh command and parse the option
pub fn run_ssh(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the initial task
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: SshArgs = serde_json::from_str(&task.parameters)?;

    // Check if the task is a file upload through ssh
    if args.upload.is_some() {
        upload::upload_file(&task.id, &args, tx, rx)?;
        return Ok(());
    }

    // Create a new SSH session and authenticate
    let sess = ssh_authenticate(&args)?;

    // Create the final user output
    let output: serde_json::Value;

    // Check if the task is for executing a shell command over ssh
    if args.exec.is_some() {
        output = exec::run_cmd(&sess, &task, &args)?;
    } else if args.download.is_some() {
        output = download::download_file(&sess, &task, &args, tx, rx)?;
    } else if let Some(ref path) = args.list {
        output = ls::ssh_list(&sess, path, &task.id, args.host.clone())?;
    } else if args.cat.is_some() {
        output = cat::ssh_cat(&sess, &task, &args)?;
    } else if args.rm.is_some() {
        output = rm::ssh_remove(&sess, &task, &args)?;
    } else {
        return Err("Failed to parse parameters".into());
    }

    // Final task output
    tx.send(output)?;
    Ok(())
}
