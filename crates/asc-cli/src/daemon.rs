//! A per-user daemon that keeps opened APKs resident, so a one-shot command
//! answers from warm caches instead of loading the APK again.
//!
//! The daemon is only an accelerator: it holds no session state, and a
//! command it runs prints byte for byte what the process would have printed
//! itself (stdout, stderr, exit status). Whenever that cannot be promised the
//! daemon declines and the client runs the command itself:
//!
//! * not forwarded at all: `--debug` (timings), `--no-cache`, and the
//!   resident or maintenance commands (`gui`, `mcp`, `cache`, `daemon`);
//! * declined: arguments the daemon cannot parse, an APK it cannot open
//!   (the error names the path as given, which only the client knows).
//!
//! One daemon serves one binary and one cache configuration: the socket name
//! hashes the executable (path, size, mtime, version), the cache settings
//! (`--cache-dir`, `--cache-max-mb`, `DROIDASC_*`, `XDG_CACHE_HOME`, `HOME`)
//! and the umask (files it writes for `-o` get the client's mode). So a
//! client never meets a daemon of another build; an upgraded binary starts
//! its own daemon, which tells the one of the old build at the same path to
//! exit.
//!
//! The socket lives in a directory only the user can enter, and both ends
//! check the other's uid. A client that disconnects (Ctrl-C) cancels its
//! search. The daemon exits after [`IDLE_EXIT`] without requests.

use crate::output::{Engines, Io};
use crate::{run_query, Cli, Common};
use asc_engine::{Engine, SharedCache};
use clap::Parser;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// `off` disables the daemon: every command runs in its own process.
pub(crate) const SWITCH_ENV: &str = "DROIDASC_DAEMON";
/// Directory of the sockets (and of the process registry); as for
/// [`asc_engine::asc_cache::ProcessRegistry::default_dir`].
const RUNTIME_DIR_ENV: &str = "DROIDASC_RUNTIME_DIR";
/// The daemon exits after this long without a request.
const IDLE_EXIT: Duration = Duration::from_secs(15 * 60);
/// How often the daemon checks for idleness.
const IDLE_POLL: Duration = Duration::from_secs(10);
/// APKs kept open; the least recently used beyond this is closed. Their
/// inflated DEX stays in the shared memory cache, under its own budget.
const MAX_ENGINES: usize = 64;
/// How long the first command waits for the daemon it starts; then it runs
/// itself. A daemon binds in a few milliseconds.
const FIRST_WAIT: Duration = Duration::from_millis(300);
/// How long `daemon start` waits for a new daemon's socket.
const START_WAIT: Duration = Duration::from_secs(5);
/// The smallest `sockaddr_un` path room of the supported systems (macOS).
const SUN_PATH_MAX: usize = 104;
/// Bytes of stdout the daemon buffers before relaying them.
const FRAME_BYTES: usize = 64 << 10;

/// Client to daemon: run a command (`[tag, cwd, argv...]`).
const REQ_RUN: u8 = b'R';
/// Client to daemon: report status.
const REQ_STATUS: u8 = b'S';
/// Client to daemon: exit once the running requests finish.
const REQ_QUIT: u8 = b'Q';
/// Daemon to client: a chunk of stdout.
const OUT: u8 = b'O';
/// Daemon to client: a chunk of stderr.
const ERR: u8 = b'E';
/// Daemon to client: the exit status (one byte); the reply ends.
const EXIT: u8 = b'X';
/// Daemon to client: run it yourself (a reason, for tests); the reply ends.
const DECLINE: u8 = b'D';
/// Daemon to client: status text.
const STATUS: u8 = b'T';

/// Commands a daemon may run for a client.
pub(crate) fn forwardable(cli: &Cli) -> bool {
    !cli.common.debug && !cli.common.no_cache && cli.command.apk_path().is_some()
}

/// Run the command in the daemon if one is up (starting one otherwise):
/// its exit status, or `None` to run it here.
pub(crate) fn forward(cli: &Cli) -> Option<u8> {
    if std::env::var_os(SWITCH_ENV).is_some_and(|v| v == "off") || !forwardable(cli) {
        return None;
    }
    let cwd = std::env::current_dir().ok()?;
    let id = Identity::of(&cli.common, &cwd)?;
    let dir = socket_dir()?;
    let sock = dir.join(id.socket_name());
    // Without a daemon, start one and hand it this command too: a cold query
    // answers sooner there (cache writes land after the reply, not before
    // the process exits) and leaves the APK warm for the next one.
    let stream = connect(&sock).or_else(|| spawn(&cli.common, &cwd).ok().and_then(|child| wait_for(&sock, child)))?;
    let mut req = Vec::new();
    put(&mut req, id.tag.as_bytes());
    put(&mut req, cwd.as_os_str().as_bytes());
    for a in std::env::args_os() {
        put(&mut req, a.as_bytes());
    }
    relay(stream, &req)
}

/// Connect to the socket a just spawned daemon binds: `None` once it exits
/// without (another daemon holds the lock, the socket cannot be bound) or
/// after [`FIRST_WAIT`].
fn wait_for(sock: &Path, mut child: std::process::Child) -> Option<UnixStream> {
    let t0 = Instant::now();
    loop {
        if let Some(stream) = connect(sock) {
            return Some(stream);
        }
        if !matches!(child.try_wait(), Ok(None)) {
            return connect(sock);
        }
        if t0.elapsed() > FIRST_WAIT {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// `droidasc daemon <action>`.
pub(crate) fn command(common: &Common, action: &crate::DaemonAction) -> Result<u8, String> {
    use crate::DaemonAction;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let dir = socket_dir().ok_or("no private runtime directory for the daemon socket")?;
    match action {
        DaemonAction::Serve => serve(common, &cwd, &dir),
        DaemonAction::Start => {
            let id = Identity::of(common, &cwd).ok_or("cannot identify this executable")?;
            let sock = dir.join(id.socket_name());
            if connect(&sock).is_none() {
                let _child = spawn(common, &cwd).map_err(|e| format!("cannot start the daemon: {e}"))?;
                let t0 = Instant::now();
                while connect(&sock).is_none() {
                    if t0.elapsed() > START_WAIT {
                        return Err("the daemon did not come up".into());
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            println!("{}", status_of(&sock).unwrap_or_default().trim_end());
            Ok(0)
        }
        DaemonAction::Status => {
            let socks = sockets(&dir);
            if socks.is_empty() {
                println!("no daemon running");
            }
            for s in socks {
                if let Some(text) = status_of(&s) {
                    println!("{}", text.trim_end());
                }
            }
            Ok(0)
        }
        DaemonAction::Stop => {
            let mut stopped = 0;
            for s in sockets(&dir) {
                if let Some(mut stream) = connect(&s) {
                    stopped += usize::from(send_frame(&mut stream, REQ_QUIT, &[]).is_ok());
                    // Wait for the daemon to remove its socket.
                    let t0 = Instant::now();
                    while s.exists() && t0.elapsed() < START_WAIT {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            }
            println!("stopped {stopped} daemon{}", if stopped == 1 { "" } else { "s" });
            Ok(0)
        }
    }
}

/// What a daemon is for: one executable build with one cache configuration.
struct Identity {
    /// Hex hash of everything below; names the socket.
    tag: String,
    /// The executable, canonical.
    exe: PathBuf,
    /// Hex hash of the build alone (version, size, mtime).
    build: String,
    /// Hex hash of the configuration alone.
    config: String,
}

impl Identity {
    fn of(common: &Common, cwd: &Path) -> Option<Identity> {
        let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
        let meta = fs::metadata(&exe).ok()?;
        let mtime = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_nanos();
        let mut build = Fnv::default();
        build.write(env!("CARGO_PKG_VERSION").as_bytes());
        build.write(&meta.len().to_le_bytes());
        build.write(&mtime.to_le_bytes());
        let mut config = Fnv::default();
        match &common.cache_dir {
            Some(d) => config.write(cwd.join(d).as_os_str().as_bytes()),
            None => config.write(b"\0default"),
        }
        config.write(&common.cache_max_mb.unwrap_or(u64::MAX).to_le_bytes());
        let mut vars: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(k, _)| {
                let k = k.as_bytes();
                (k.starts_with(b"DROIDASC_") && !k.starts_with(SWITCH_ENV.as_bytes())) || k == b"XDG_CACHE_HOME" || k == b"HOME"
            })
            .collect();
        vars.sort();
        for (k, v) in &vars {
            config.write(k.as_bytes());
            config.write(b"=");
            config.write(v.as_bytes());
        }
        config.write(&umask().to_le_bytes());
        let (build, config) = (build.finish(), config.finish());
        let mut all = Fnv::default();
        all.write(exe.as_os_str().as_bytes());
        all.write(&build.to_le_bytes());
        all.write(&config.to_le_bytes());
        Some(Identity { tag: format!("{:016x}", all.finish()), exe, build: format!("{build:016x}"), config: format!("{config:016x}") })
    }

    fn socket_name(&self) -> String {
        format!("{}.sock", self.tag)
    }
}

/// 64-bit FNV-1a: stable across builds, unlike `DefaultHasher`.
struct Fnv(u64);

impl Default for Fnv {
    fn default() -> Fnv {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
}

impl Fnv {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
        }
        // Field separator, so ("ab", "c") and ("a", "bc") differ.
        self.0 = (self.0 ^ 0xff).wrapping_mul(0x100_0000_01b3);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// The process's umask (read by setting and restoring it: only while the
/// process is still single-threaded, at startup).
#[allow(clippy::useless_conversion)] // `mode_t` is u32 on Linux but u16 on macOS
fn umask() -> u32 {
    // SAFETY: umask only swaps the process's file mode mask; it is restored
    // at once and no other thread creates files yet.
    unsafe {
        let m = libc::umask(0o022);
        libc::umask(m);
        u32::from(m)
    }
}

fn uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

/// The uid of the process at the other end of `stream`.
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let fd = stream.as_raw_fd();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for writes of the sizes passed.
        let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &raw mut len) };
        (rc == 0).then_some(cred.uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: both out-pointers are valid for writes.
        let rc = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
        (rc == 0).then_some(uid)
    }
}

/// `$DROIDASC_RUNTIME_DIR/daemon`, `$XDG_RUNTIME_DIR/droidasc/daemon` or
/// `<temp dir>/droidasc-<uid>/daemon`, created private; `None` if it (or its
/// parent) belongs to someone else or others may enter it.
fn socket_dir() -> Option<PathBuf> {
    let base = match (std::env::var_os(RUNTIME_DIR_ENV), std::env::var_os("XDG_RUNTIME_DIR")) {
        (Some(d), _) => PathBuf::from(d),
        (None, Some(d)) => PathBuf::from(d).join("droidasc"),
        (None, None) => std::env::temp_dir().join(format!("droidasc-{}", uid())),
    };
    let dir = base.join("daemon");
    // `<tag>.sock` must fit `sockaddr_un` (104 bytes on macOS, 108 on Linux).
    if dir.as_os_str().len() + "/0123456789abcdef.sock".len() >= SUN_PATH_MAX {
        return None;
    }
    let _ = fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir);
    (private(&base) && private(&dir)).then_some(dir)
}

/// Owned by this user and closed to everyone else.
fn private(dir: &Path) -> bool {
    fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir() && m.uid() == uid() && m.mode() & 0o077 == 0)
}

/// A daemon's socket, if one answers there as this user.
fn connect(sock: &Path) -> Option<UnixStream> {
    let stream = UnixStream::connect(sock).ok()?;
    (peer_uid(&stream) == Some(uid())).then_some(stream)
}

fn sockets(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "sock")).collect())
        .unwrap_or_default();
    out.sort();
    out
}

fn status_of(sock: &Path) -> Option<String> {
    let mut stream = connect(sock)?;
    send_frame(&mut stream, REQ_STATUS, &[]).ok()?;
    let (tag, body) = read_frame(&mut stream).ok()??;
    (tag == STATUS).then(|| String::from_utf8_lossy(&body).into_owned())
}

/// Start `droidasc daemon serve` for `common`'s configuration, detached
/// from this process and its terminal.
fn spawn(common: &Common, cwd: &Path) -> io::Result<std::process::Child> {
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["daemon", "serve"]);
    if let Some(d) = &common.cache_dir {
        cmd.arg("--cache-dir").arg(cwd.join(d));
    }
    if let Some(mb) = common.cache_max_mb {
        cmd.arg("--cache-max-mb").arg(mb.to_string());
    }
    if let Some(mb) = common.memory_mb {
        cmd.arg("--memory-mb").arg(mb.to_string());
    }
    cmd.current_dir("/").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe and touches no memory of the parent.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    // Not reaped: it outlives this process (and is adopted by init).
    cmd.spawn()
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("argument under 4 GiB");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// The length-prefixed fields of a request.
fn fields(mut body: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !body.is_empty() {
        let len = u32::from_le_bytes(body.get(..4)?.try_into().ok()?) as usize;
        out.push(body.get(4..4 + len)?);
        body = &body[4 + len..];
    }
    Some(out)
}

fn send_frame(w: &mut impl Write, tag: u8, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.push(tag);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(body);
    w.write_all(&frame)
}

/// The next frame, or `None` at a clean end of stream.
fn read_frame(r: &mut impl Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let mut body = vec![0; len];
    r.read_exact(&mut body)?;
    Ok(Some((head[0], body)))
}

/// Send the request and copy the reply to this process's stdout / stderr:
/// the exit status, or `None` when the daemon declined (or vanished) before
/// any output, so the command runs here.
fn relay(mut stream: UnixStream, req: &[u8]) -> Option<u8> {
    send_frame(&mut stream, REQ_RUN, req).ok()?;
    let (stdout, stderr) = (io::stdout(), io::stderr());
    let (mut out, mut err) = (stdout.lock(), stderr.lock());
    let mut out_open = true;
    let mut started = false;
    loop {
        match read_frame(&mut stream) {
            Ok(Some((OUT, body))) => {
                started = true;
                // A closed stdout (`| head`) drops the rest, as a local run does.
                if out_open && out.write_all(&body).and_then(|()| out.flush()).is_err() {
                    out_open = false;
                }
            }
            Ok(Some((ERR, body))) => {
                started = true;
                let _ = err.write_all(&body);
            }
            Ok(Some((EXIT, body))) => return Some(body.first().copied().unwrap_or(1)),
            Ok(Some((DECLINE, _))) if !started => return None,
            Ok(_) | Err(_) if !started => return None,
            Ok(_) | Err(_) => {
                let _ = writeln!(err, "Error: the droidasc daemon went away mid-command");
                return Some(1);
            }
        }
    }
}

/// The resident state of a daemon.
struct Daemon {
    id: Identity,
    cache: SharedCache,
    engines: Mutex<Pool>,
    /// Requests running now.
    active: AtomicUsize,
    /// Commands run (declined ones aside).
    served: AtomicUsize,
    last: Mutex<Instant>,
    started: Instant,
    sock: PathBuf,
    pid_file: PathBuf,
    /// Set once the daemon is shutting down.
    quitting: AtomicBool,
}

#[derive(Default)]
struct Pool {
    /// `(canonical APK path, threads)` -> engine and its last use.
    engines: HashMap<(PathBuf, usize), (Arc<Engine>, u64)>,
    tick: u64,
}

impl Engines for Daemon {
    fn engine(&self, common: &Common, apk_path: &Path) -> Arc<Engine> {
        let path = fs::canonicalize(apk_path).unwrap_or_else(|_| apk_path.to_path_buf());
        let mut pool = self.engines.lock().expect("engine pool mutex poisoned");
        pool.tick += 1;
        let tick = pool.tick;
        let key = (path, common.threads);
        if let Some((engine, used)) = pool.engines.get_mut(&key) {
            *used = tick;
            return Arc::clone(engine);
        }
        if pool.engines.len() >= MAX_ENGINES {
            let oldest = pool.engines.iter().min_by_key(|(_, (_, used))| *used).map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                pool.engines.remove(&k);
            }
        }
        // As `Common::engine`, but on the shared resident cache; its debug
        // output is off (`--debug` is never forwarded).
        let engine = Arc::new(Engine::new(&key.0).with_threads(common.threads).with_logger(|_| {}).with_shared_cache(&self.cache));
        pool.engines.insert(key, (Arc::clone(&engine), tick));
        engine
    }
}

/// `droidasc daemon serve`: bind the socket and answer until idle.
fn serve(common: &Common, cwd: &Path, dir: &Path) -> Result<u8, String> {
    let id = Identity::of(common, cwd).ok_or("cannot identify this executable")?;
    // One daemon per identity: the lock is held for the daemon's lifetime.
    let lock_path = dir.join(format!("{}.lock", id.tag));
    let lock = File::create(&lock_path).map_err(|e| format!("cannot open {}: {e}", lock_path.display()))?;
    // SAFETY: flock on a descriptor this process owns.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Ok(0); // another daemon has it
    }
    let sock = dir.join(id.socket_name());
    let _ = fs::remove_file(&sock); // a dead daemon's: we hold the lock
    let listener = UnixListener::bind(&sock).map_err(|e| format!("cannot bind {}: {e}", sock.display()))?;
    let _ = fs::set_permissions(&sock, fs::Permissions::from_mode(0o600));
    let pid_file = dir.join(format!("{}.pid", id.tag));
    let _ = fs::write(&pid_file, format!("{}\n{}\n{}\n{}\n", std::process::id(), id.exe.display(), id.build, id.config));
    retire_older_builds(dir, &id);
    let daemon = Arc::new(Daemon {
        cache: SharedCache::new(common.resident_cache(), |_| {}),
        engines: Mutex::new(Pool::default()),
        active: AtomicUsize::new(0),
        served: AtomicUsize::new(0),
        last: Mutex::new(Instant::now()),
        started: Instant::now(),
        sock,
        pid_file,
        quitting: AtomicBool::new(false),
        id,
    });
    {
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || loop {
            std::thread::sleep(IDLE_POLL);
            let idle = daemon.last.lock().expect("idle clock mutex poisoned").elapsed();
            if daemon.active.load(Ordering::SeqCst) == 0 && idle > IDLE_EXIT {
                daemon.shutdown(0);
            }
        });
    }
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if peer_uid(&stream) != Some(uid()) {
            continue;
        }
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || daemon.handle(stream));
    }
    drop(lock);
    Ok(0)
}

/// Ask the daemons of other builds of this executable (same path and
/// configuration) to exit: the binary they ran has been replaced.
fn retire_older_builds(dir: &Path, id: &Identity) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "pid") || path.file_stem() == Some(OsStr::new(&id.tag)) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else { continue };
        let lines: Vec<&str> = text.lines().collect();
        let [_, exe, build, config] = lines[..] else { continue };
        if Path::new(exe) == id.exe && config == id.config && build != id.build {
            if let Some(mut stream) = connect(&path.with_extension("sock")) {
                let _ = send_frame(&mut stream, REQ_QUIT, &[]);
            }
        }
    }
}

impl Daemon {
    fn handle(&self, mut stream: UnixStream) {
        let Ok(Some((kind, body))) = read_frame(&mut stream) else { return };
        match kind {
            REQ_RUN => {
                self.active.fetch_add(1, Ordering::SeqCst);
                if self.run(stream, &body) {
                    self.served.fetch_add(1, Ordering::Relaxed);
                }
                *self.last.lock().expect("idle clock mutex poisoned") = Instant::now();
                self.active.fetch_sub(1, Ordering::SeqCst);
            }
            REQ_STATUS => {
                let _ = send_frame(&mut stream, STATUS, self.status().as_bytes());
            }
            REQ_QUIT => {
                drop(stream);
                self.shutdown(0);
            }
            _ => {}
        }
    }

    fn status(&self) -> String {
        let open = self.engines.lock().expect("engine pool mutex poisoned").engines.len();
        format!(
            "pid {}, up {} s, {} requests ({} running), {open} APKs open, memory cache {} of {} MiB, {} ({})\n",
            std::process::id(),
            self.started.elapsed().as_secs(),
            self.served.load(Ordering::Relaxed),
            self.active.load(Ordering::SeqCst),
            self.cache.memory_bytes() >> 20,
            self.cache.memory_capacity() >> 20,
            self.id.exe.display(),
            self.id.tag,
        )
    }

    /// Stop taking requests, let the running ones finish, land the queued
    /// cache writes and exit.
    fn shutdown(&self, code: i32) -> ! {
        if !self.quitting.swap(true, Ordering::SeqCst) {
            let _ = fs::remove_file(&self.sock);
            let _ = fs::remove_file(&self.pid_file);
        }
        while self.active.load(Ordering::SeqCst) > 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.cache.flush_writes();
        std::process::exit(code)
    }

    /// Run a client's command; `false` if it was declined.
    fn run(&self, stream: UnixStream, body: &[u8]) -> bool {
        let decline = |mut s: &UnixStream, why: &str| {
            let _ = send_frame(&mut s, DECLINE, why.as_bytes());
            false
        };
        let Some(fields) = fields(body) else { return decline(&stream, "malformed request") };
        let [tag, cwd, argv @ ..] = &fields[..] else { return decline(&stream, "malformed request") };
        if *tag != self.id.tag.as_bytes() {
            return decline(&stream, "another build or configuration");
        }
        let cwd = PathBuf::from(OsStr::from_bytes(cwd));
        let argv: Vec<OsString> = argv.iter().map(|a| OsString::from_vec(a.to_vec())).collect();
        let Ok(cli) = Cli::try_parse_from(&argv) else { return decline(&stream, "arguments") };
        if !forwardable(&cli) {
            return decline(&stream, "not forwardable");
        }
        // Open failures name the path as given: leave them to the client.
        let apk = cli.command.apk_path().map(|p| cwd.join(p));
        if !apk.as_deref().is_some_and(|p| File::open(p).and_then(|f| f.metadata()).is_ok_and(|m| m.is_file())) {
            return decline(&stream, "APK not readable");
        }
        let cancel = Arc::new(AtomicBool::new(false));
        watch_disconnect(&stream, Arc::clone(&cancel));
        let frames = Rc::new(RefCell::new(Frames { stream, out: Vec::new(), failed: false }));
        let (mut out, mut err) = (FrameOut(Rc::clone(&frames)), FrameErr(Rc::clone(&frames)));
        let code = {
            let mut io = Io::new(&mut out, &mut err, self, &cancel).with_cwd(&cwd);
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_query(&mut io, &cli.common, cli.command, Instant::now())));
            match result {
                Ok(Ok(code)) => code,
                Ok(Err(e)) => {
                    io.note(format_args!("Error: {e}"));
                    1
                }
                // The client reports the lost daemon; the panic is not ours to print.
                Err(_) => return true,
            }
        };
        let mut frames = frames.borrow_mut();
        if frames.send_out().is_ok() {
            let _ = send_frame(&mut frames.stream, EXIT, &[code]);
        }
        let _ = frames.stream.shutdown(std::net::Shutdown::Both);
        true
    }
}

/// Set `cancel` once the client hangs up (it sends nothing after the request).
fn watch_disconnect(stream: &UnixStream, cancel: Arc<AtomicBool>) {
    let Ok(mut reader) = stream.try_clone() else { return };
    std::thread::spawn(move || {
        let mut byte = [0u8; 1];
        while matches!(reader.read(&mut byte), Ok(n) if n > 0) {}
        cancel.store(true, Ordering::Relaxed);
    });
}

/// The reply stream of one request: buffered stdout, unbuffered stderr, in
/// the order the command wrote them.
struct Frames {
    stream: UnixStream,
    out: Vec<u8>,
    failed: bool,
}

impl Frames {
    fn send(&mut self, tag: u8, body: &[u8]) -> io::Result<()> {
        if self.failed {
            return Err(ErrorKind::BrokenPipe.into());
        }
        send_frame(&mut self.stream, tag, body).inspect_err(|_| self.failed = true)
    }

    fn send_out(&mut self) -> io::Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        let out = std::mem::take(&mut self.out);
        self.send(OUT, &out)
    }
}

/// The command's stdout.
struct FrameOut(Rc<RefCell<Frames>>);

impl Write for FrameOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut f = self.0.borrow_mut();
        if f.failed {
            return Err(ErrorKind::BrokenPipe.into());
        }
        f.out.extend_from_slice(buf);
        if f.out.len() >= FRAME_BYTES {
            f.send_out()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().send_out()
    }
}

/// The command's stderr: sent at once, after the stdout written before it.
struct FrameErr(Rc<RefCell<Frames>>);

impl Write for FrameErr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut f = self.0.borrow_mut();
        f.send_out()?;
        f.send(ERR, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_end_cleanly() {
        let mut buf = Vec::new();
        send_frame(&mut buf, OUT, b"hello").unwrap();
        send_frame(&mut buf, EXIT, &[2]).unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).unwrap(), Some((OUT, b"hello".to_vec())));
        assert_eq!(read_frame(&mut r).unwrap(), Some((EXIT, vec![2])));
        assert_eq!(read_frame(&mut r).unwrap(), None);
    }

    #[test]
    fn request_fields_round_trip() {
        let mut req = Vec::new();
        for f in [&b"tag"[..], b"", b"/a b/c"] {
            put(&mut req, f);
        }
        assert_eq!(fields(&req).unwrap(), vec![&b"tag"[..], b"", b"/a b/c"]);
        assert!(fields(&req[..req.len() - 1]).is_none(), "a truncated field is refused");
    }

    #[test]
    fn peer_uid_is_ours_on_a_socket_pair() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a), Some(uid()));
    }

    #[test]
    fn hanging_up_cancels_the_request() {
        let (daemon_end, client_end) = UnixStream::pair().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        watch_disconnect(&daemon_end, Arc::clone(&cancel));
        assert!(!cancel.load(Ordering::Relaxed));
        drop(client_end);
        let t0 = Instant::now();
        while !cancel.load(Ordering::Relaxed) {
            assert!(t0.elapsed() < Duration::from_secs(5), "cancel not set after the client hung up");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn only_private_directories_hold_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("d");
        fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
        assert!(private(&d));
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!private(&d), "others may enter it");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(!private(&link), "a symlink is not followed");
    }

    #[test]
    fn stderr_follows_the_stdout_written_before_it() {
        let (daemon_end, mut client_end) = UnixStream::pair().unwrap();
        let frames = Rc::new(RefCell::new(Frames { stream: daemon_end, out: Vec::new(), failed: false }));
        let (mut out, mut err) = (FrameOut(Rc::clone(&frames)), FrameErr(Rc::clone(&frames)));
        out.write_all(b"row\n").unwrap();
        err.write_all(b"warn\n").unwrap();
        out.write_all(b"tail\n").unwrap();
        out.flush().unwrap();
        drop((out, err, frames));
        let got: Vec<_> = std::iter::from_fn(|| read_frame(&mut client_end).unwrap()).collect();
        assert_eq!(got, vec![(OUT, b"row\n".to_vec()), (ERR, b"warn\n".to_vec()), (OUT, b"tail\n".to_vec())]);
    }
}
