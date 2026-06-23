use clap::{Parser, Subcommand};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::{sleep, Duration},
};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "zalitunnel", about = "ZaliTunnel — Reverse TCP tunnel via VPS")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Server {
        #[arg(long, default_value = "7000")]
        tunnel_port: u16,
        #[arg(long, default_value = "25565")]
        public_port: u16,
        #[arg(long, default_value = "10")]
        pool_size: usize,
    },
    Client {
        #[arg(long)]
        server: String,
        #[arg(long, default_value = "7000")]
        tunnel_port: u16,
        #[arg(long, default_value = "127.0.0.1:25565")]
        local: String,
        #[arg(long, default_value = "10")]
        pool_size: usize,
    },
}

// Protocol (control channel):
//   Client → Server: [0x01]           READY
//   Server → Client: [0x02][id:4]     RELAY — public user arrived, open data conn with this id
//   Server → Client: [0x03]           PING
//   Client → Server: [0x04]           PONG
//
// Data channel (separate port = tunnel_port + 1):
//   Client → Server: [0x05][id:4]     identify which request this pipe belongs to
//   Then raw TCP relay.

const MSG_READY: u8 = 0x01;
const MSG_RELAY: u8 = 0x02;
const MSG_PING:  u8 = 0x03;
const MSG_PONG:  u8 = 0x04;
const MSG_DATA:  u8 = 0x05;

// ─── SERVER ─────────────────────────────────────────────────────────────────

async fn run_server(tunnel_port: u16, public_port: u16, pool_size: usize) -> anyhow::Result<()> {
    let data_port = tunnel_port + 1;

    // ready_tx: control slots register themselves here (id → oneshot sender of request_id)
    // When a public user arrives, we pop one slot and send it the request_id.
    let (slot_tx, mut slot_rx) = mpsc::channel::<(u32, oneshot::Sender<u32>)>(64);

    // data_tx: data connections register here (request_id → TcpStream)
    let (data_tx, mut data_rx) = mpsc::channel::<(u32, TcpStream)>(64);

    // pending public conns: keyed by request_id
    let pending: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u32, TcpStream>>> =
        Default::default();

    let ctrl_listener   = TcpListener::bind(("0.0.0.0", tunnel_port)).await?;
    let data_listener   = TcpListener::bind(("0.0.0.0", data_port)).await?;
    let public_listener = TcpListener::bind(("0.0.0.0", public_port)).await?;

    info!("Server started");
    info!("  Control port : {tunnel_port}");
    info!("  Data port    : {data_port}");
    info!("  Public port  : {public_port}");

    // Accept control connections
    {
        let slot_tx = slot_tx.clone();
        tokio::spawn(async move {
            let mut next_id: u32 = 0;
            loop {
                match ctrl_listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("Control from {addr}");
                        let id = next_id;
                        next_id = next_id.wrapping_add(1);
                        let tx = slot_tx.clone();
                        tokio::spawn(handle_control(stream, id, tx));
                    }
                    Err(e) => error!("Control accept: {e}"),
                }
            }
        });
    }

    // Accept data connections
    {
        let data_tx = data_tx.clone();
        tokio::spawn(async move {
            loop {
                match data_listener.accept().await {
                    Ok((stream, _)) => {
                        let tx = data_tx.clone();
                        tokio::spawn(handle_data_conn(stream, tx));
                    }
                    Err(e) => error!("Data accept: {e}"),
                }
            }
        });
    }

    // Accept public connections — store in pending, notify a ready slot
    {
        let pending = pending.clone();
        let slot_tx = slot_tx.clone(); // unused, we use slot_rx below
        // We need to send request_id to a waiting slot.
        // Use a separate channel for "public arrived" events.
        let (pub_tx, mut pub_rx) = mpsc::channel::<(u32, TcpStream)>(64);
        tokio::spawn(async move {
            let mut next_id: u32 = 1_000_000;
            loop {
                match public_listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("Public from {addr}");
                        let id = next_id;
                        next_id = next_id.wrapping_add(1);
                        let _ = pub_tx.send((id, stream)).await;
                    }
                    Err(e) => error!("Public accept: {e}"),
                }
            }
        });

        // Dispatcher: pair public conn with a ready slot
        let pending2 = pending.clone();
        tokio::spawn(async move {
            loop {
                // Wait for a public user
                let (request_id, public_stream) = match pub_rx.recv().await {
                    Some(x) => x,
                    None => break,
                };
                // Wait for a ready control slot
                let (_slot_id, notify) = match slot_rx.recv().await {
                    Some(x) => x,
                    None => break,
                };
                // Store public conn, notify slot
                pending2.lock().await.insert(request_id, public_stream);
                let _ = notify.send(request_id);
            }
        });
    }

    // Pair data pipes with pending public conns
    loop {
        let (request_id, data_stream) = match data_rx.recv().await {
            Some(x) => x,
            None => break,
        };
        let public_stream = pending.lock().await.remove(&request_id);
        match public_stream {
            Some(ps) => {
                info!("Relaying id={request_id}");
                tokio::spawn(relay(ps, data_stream));
            }
            None => warn!("No pending conn for id={request_id}"),
        }
    }

    Ok(())
}

async fn handle_control(mut stream: TcpStream, id: u32, slot_tx: mpsc::Sender<(u32, oneshot::Sender<u32>)>) {
    let mut buf = [0u8; 1];
    match stream.read_exact(&mut buf).await {
        Ok(_) if buf[0] == MSG_READY => info!("Slot {id} ready"),
        Ok(_) => { warn!("Bad READY byte: 0x{:02x}", buf[0]); return; }
        Err(e) => { warn!("Control handshake: {e}"); return; }
    }

    let (tx, rx) = oneshot::channel::<u32>();
    if slot_tx.send((id, tx)).await.is_err() {
        return;
    }

    // Wait for a request_id
    let request_id = tokio::select! {
        res = rx => match res { Ok(rid) => rid, Err(_) => return },
        _ = async {
            loop {
                sleep(Duration::from_secs(30)).await;
                if stream.write_all(&[MSG_PING]).await.is_err() { break; }
                let mut pong = [0u8; 1];
                let _ = stream.read_exact(&mut pong).await;
            }
        } => return,
    };

    // Send RELAY + request_id to client
    let mut msg = [MSG_RELAY, 0, 0, 0, 0];
    msg[1..5].copy_from_slice(&request_id.to_be_bytes());
    if let Err(e) = stream.write_all(&msg).await {
        warn!("Send RELAY: {e}");
    }
    // Control conn done — client will open a data conn
}

async fn handle_data_conn(mut stream: TcpStream, tx: mpsc::Sender<(u32, TcpStream)>) {
    let mut buf = [0u8; 5];
    match stream.read_exact(&mut buf).await {
        Ok(_) if buf[0] == MSG_DATA => {
            let id = u32::from_be_bytes(buf[1..5].try_into().unwrap());
            info!("Data pipe id={id}");
            let _ = tx.send((id, stream)).await;
        }
        Ok(_) => warn!("Bad DATA byte: 0x{:02x}", buf[0]),
        Err(e) => warn!("Data handshake: {e}"),
    }
}

// ─── CLIENT ─────────────────────────────────────────────────────────────────

async fn run_client(server: String, tunnel_port: u16, local: String, pool_size: usize) -> anyhow::Result<()> {
    let data_port = tunnel_port + 1;
    info!("Client started");
    info!("  VPS       : {server}:{tunnel_port}");
    info!("  Data port : {data_port}");
    info!("  Local     : {local}");
    info!("  Pool size : {pool_size}");

    let (done_tx, mut done_rx) = mpsc::channel::<()>(pool_size * 2);
    for _ in 0..pool_size {
        tokio::spawn(control_slot(
            server.clone(), tunnel_port, data_port, local.clone(), done_tx.clone(),
        ));
    }
    while done_rx.recv().await.is_some() {
        tokio::spawn(control_slot(
            server.clone(), tunnel_port, data_port, local.clone(), done_tx.clone(),
        ));
    }
    Ok(())
}

async fn control_slot(
    server: String, tunnel_port: u16, data_port: u16, local: String, done_tx: mpsc::Sender<()>,
) {
    let ctrl_addr = format!("{server}:{tunnel_port}");
    loop {
        match TcpStream::connect(&ctrl_addr).await {
            Ok(mut ctrl) => {
                if ctrl.write_all(&[MSG_READY]).await.is_err() {
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
                info!("Control slot ready");

                // Wait for RELAY (1 byte) + id (4 bytes), handling pings
                let request_id = loop {
                    let mut b = [0u8; 1];
                    match ctrl.read_exact(&mut b).await {
                        Ok(_) if b[0] == MSG_RELAY => {
                            let mut id_buf = [0u8; 4];
                            if ctrl.read_exact(&mut id_buf).await.is_err() {
                                break None;
                            }
                            break Some(u32::from_be_bytes(id_buf));
                        }
                        Ok(_) if b[0] == MSG_PING => {
                            let _ = ctrl.write_all(&[MSG_PONG]).await;
                        }
                        Ok(_) => { warn!("Unexpected: 0x{:02x}", b[0]); break None; }
                        Err(e) => { warn!("Control read: {e}"); break None; }
                    }
                };

                let request_id = match request_id {
                    Some(id) => id,
                    None => { sleep(Duration::from_secs(2)).await; continue; }
                };

                info!("Got RELAY id={request_id}");
                let _ = done_tx.send(()).await; // spawn replacement

                // Open data connection
                let data_addr = format!("{server}:{data_port}");
                match TcpStream::connect(&data_addr).await {
                    Ok(mut data_conn) => {
                        let mut header = [MSG_DATA, 0, 0, 0, 0];
                        header[1..5].copy_from_slice(&request_id.to_be_bytes());
                        if data_conn.write_all(&header).await.is_err() {
                            return;
                        }
                        match TcpStream::connect(&local).await {
                            Ok(local_conn) => relay(data_conn, local_conn).await,
                            Err(e) => error!("Cannot connect to {local}: {e}"),
                        }
                    }
                    Err(e) => error!("Cannot open data conn to {data_addr}: {e}"),
                }
                return;
            }
            Err(e) => warn!("Cannot connect to {ctrl_addr}: {e}"),
        }
        sleep(Duration::from_secs(3)).await;
    }
}

// ─── RELAY ──────────────────────────────────────────────────────────────────

async fn relay(a: TcpStream, b: TcpStream) {
    let (mut ar, mut aw) = io::split(a);
    let (mut br, mut bw) = io::split(b);

    let a_to_b = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = ar.read(&mut buf).await?;
            if n == 0 { break; }
            bw.write_all(&buf[..n]).await?;
        }
        bw.shutdown().await?;
        Ok::<_, io::Error>(())
    };
    let b_to_a = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = br.read(&mut buf).await?;
            if n == 0 { break; }
            aw.write_all(&buf[..n]).await?;
        }
        aw.shutdown().await?;
        Ok::<_, io::Error>(())
    };

    tokio::select! {
        r = a_to_b => { if let Err(e) = r { warn!("a→b: {e}") } }
        r = b_to_a => { if let Err(e) = r { warn!("b→a: {e}") } }
    }
    info!("Relay done");
}

// ─── MAIN ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).with_level(true).init();
    let cli = Cli::parse();
    match cli.mode {
        Mode::Server { tunnel_port, public_port, pool_size } =>
            run_server(tunnel_port, public_port, pool_size).await?,
        Mode::Client { server, tunnel_port, local, pool_size } =>
            run_client(server, tunnel_port, local, pool_size).await?,
    }
    Ok(())
}
