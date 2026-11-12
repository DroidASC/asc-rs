//! A tiny HTTP/1.1 server on `127.0.0.1` for tests that download: fixed
//! routes, a log of the paths asked for, nothing else. No test reaches the
//! network.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Default)]
struct Routes {
    bodies: HashMap<String, (u16, Vec<u8>)>,
    requests: Vec<String>,
    delay: Duration,
}

/// The server; it stops when dropped.
pub struct HttpServer {
    addr: SocketAddr,
    routes: Arc<Mutex<Routes>>,
    stop: Arc<AtomicBool>,
}

impl HttpServer {
    /// A server on a free port, answering 404 until routes are added.
    ///
    /// # Panics
    ///
    /// If no port on 127.0.0.1 can be bound.
    pub fn start() -> HttpServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
        let addr = listener.local_addr().expect("bound address");
        let routes = Arc::new(Mutex::new(Routes::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (shared, stopped) = (Arc::clone(&routes), Arc::clone(&stop));
        thread::spawn(move || {
            for stream in listener.incoming() {
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let routes = Arc::clone(&shared);
                thread::spawn(move || serve(stream, &routes));
            }
        });
        HttpServer { addr, routes, stop }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Answers `path` with `status` and `body`.
    ///
    /// # Panics
    ///
    /// If a connection thread panicked while holding the routes.
    pub fn route(&self, path: &str, status: u16, body: impl Into<Vec<u8>>) {
        self.lock().bodies.insert(path.to_string(), (status, body.into()));
    }

    /// Waits this long before each answer (to make requests overlap).
    ///
    /// # Panics
    ///
    /// As [`HttpServer::route`].
    pub fn delay(&self, delay: Duration) {
        self.lock().delay = delay;
    }

    /// The paths asked for so far, in order.
    ///
    /// # Panics
    ///
    /// As [`HttpServer::route`].
    pub fn requests(&self) -> Vec<String> {
        self.lock().requests.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Routes> {
        self.routes.lock().expect("http fixture routes mutex poisoned")
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wakes the accept loop up so it sees the flag.
        let _ = TcpStream::connect(self.addr);
    }
}

/// Answers one request and closes the connection.
fn serve(stream: TcpStream, routes: &Mutex<Routes>) {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    // `GET <path> HTTP/1.1`, then headers up to an empty line.
    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header.trim().is_empty() => break,
            Ok(_) => {}
        }
    }
    let (status, body, delay) = {
        let mut routes = routes.lock().expect("http fixture routes mutex poisoned");
        routes.requests.push(path.clone());
        let (status, body) = routes.bodies.get(&path).cloned().unwrap_or((404, b"not found".to_vec()));
        (status, body, routes.delay)
    };
    thread::sleep(delay);
    let head = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let mut stream = &stream;
    let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(&body));
}
