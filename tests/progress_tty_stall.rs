//! WP-PROGRESS S4 remediation: a stalled terminal and the production surface.
//!
//! The renderer's tests used stand-in surfaces for a stalled terminal, so the
//! one thing the production surface does that a stand-in does not (take
//! `std::io::stderr()`'s process-wide lock for the length of a blocking write)
//! was never exercised. These tests run the **production**
//! `stderr_consumer_factory()` against a **real pty** whose output buffer is
//! full and is not drained, inside a child process whose fd 2 is that pty.
//!
//! What a blocked progress write may and may not do:
//!
//! * `end()` gives up after its bound and reports `Abandoned`;
//! * the main thread's `eprintln!` still completes. The blocked write is parked
//!   in the kernel on its own descriptor, so fd 2 is pointed at a healthy pipe
//!   afterwards: if the worker held `Stderr`'s lock, `eprintln!` could not
//!   return even though its destination is fine;
//! * the abandoned worker writes nothing after the bound: once the terminal
//!   drains, the only progress bytes that ever arrive are the one frame whose
//!   write was already blocked (no queued frame, no erase);
//! * the surface's descriptor is private, blocking, and closed again.
//!
//! WP-PROGRESS S5 runs the same stalled terminal against the production plain
//! renderer (`stderr_plain_consumer_factory()`), which shares the surface, and
//! adds the panic path (RA-L1): a run that panics detaches its
//! progress worker, which must then be mute (see `child_panic`).
//!
//! Each scenario runs in its own child (this same test binary re-executed with
//! `SINTER_STALL_MODE` set) so fd 2, the descriptor table and the stalled worker
//! belong to a process nothing else shares. A watchdog ends a child that hangs.
#![cfg(unix)]

use sinter::progress::{ItemKind, ItemRef, ProgressEvent, RunKind, RunOutcome, Stage};
use sinter::progress_plain::stderr_plain_consumer_factory;
use sinter::progress_session::{ProgressMode, ProgressOptions, SessionInfo, Teardown};
use sinter::progress_tty::stderr_consumer_factory;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::FromRawFd;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const CLEAR: &str = "\r\x1b[2K";
const MODE_VAR: &str = "SINTER_STALL_MODE";
const PANIC_MARK: &str = "PANIC-MARK";

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

// ---------------------------------------------------------------------------
// child side
// ---------------------------------------------------------------------------

/// Report a fact to the parent (stdout is a pipe; stderr is the stalled pty).
fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "STALL:{line}");
    let _ = out.flush();
}

fn fd_count() -> usize {
    open_fds().len()
}

fn open_fds() -> Vec<i32> {
    (0..1024)
        // SAFETY: F_GETFD only queries a descriptor number.
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } != -1)
        .collect()
}

/// The file status flags that matter here: access mode and `O_NONBLOCK`
/// (macOS also reports internal bits such as `FWASWRITTEN` after a write).
fn status_flags(fd: i32) -> i32 {
    // SAFETY: F_GETFL only queries a descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags & (libc::O_ACCMODE | libc::O_NONBLOCK)
}

fn full_status_flags(fd: i32) -> i32 {
    // SAFETY: F_GETFL only queries a descriptor.
    unsafe { libc::fcntl(fd, libc::F_GETFL) }
}

fn set_nonblocking(fd: i32, on: bool) {
    let flags = full_status_flags(fd);
    let flags = if on {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: plain flag change on a descriptor of this process.
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
}

/// Fill fd 2's output buffer (nobody reads the master), so the next blocking
/// write to it stalls.
///
/// "Full" is only believed once nothing could be written for `SETTLE`: Linux
/// frees pty room asynchronously (the flip buffer is flushed into the line
/// discipline after the first `EAGAIN`), so a stop at the first failure can
/// leave room for a small line and the "stalled" worker would not stall.
fn fill_stderr() {
    const SETTLE: Duration = Duration::from_millis(150);
    set_nonblocking(2, true);
    let chunk = [b'.'; 512];
    let mut filled = 0usize;
    let mut last_written = Instant::now();
    loop {
        // SAFETY: writes a live buffer to fd 2.
        let n = unsafe { libc::write(2, chunk.as_ptr().cast(), chunk.len()) };
        if n >= 0 {
            filled += n as usize;
            last_written = Instant::now();
            if filled > 16 * 1024 * 1024 {
                say("FAIL the pty never filled up");
                std::process::exit(1);
            }
        } else if last_written.elapsed() >= SETTLE {
            break;
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    set_nonblocking(2, false);
}

fn options(bound: Duration) -> ProgressOptions {
    ProgressOptions::new(ProgressMode::Tty)
        .with_consumer_factory(stderr_consumer_factory())
        .with_teardown_bound(bound)
}

fn info(references_secrets: bool) -> SessionInfo {
    SessionInfo {
        kind: RunKind::Apply,
        references_secrets,
    }
}

fn watchdog() {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(40));
        say("FAIL watchdog: the child hung");
        std::process::exit(99);
    });
}

fn wait_for_go() {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

fn child_stalled() {
    watchdog();
    fill_stderr();
    let before = open_fds();
    let flags_before = status_flags(2);

    let opts = options(ms(200));
    let session = opts.begin(info(false));
    let sink = session.sink();
    // The first frame: the worker blocks in the kernel writing it.
    sink.emit(&ProgressEvent::StageStarted {
        stage: Stage::Connect,
        total: None,
    });
    std::thread::sleep(ms(200));

    // The descriptor the surface made: private, blocking, and stderr's own
    // status flags are untouched.
    let new: Vec<i32> = open_fds()
        .into_iter()
        .filter(|fd| !before.contains(fd))
        .collect();
    say(&format!("NEWFDS {}", new.len()));
    for fd in &new {
        say(&format!(
            "NEWFD_NONBLOCK {}",
            status_flags(*fd) & libc::O_NONBLOCK != 0
        ));
    }
    say(&format!(
        "STDERR_FLAGS_UNCHANGED {}",
        status_flags(2) == flags_before && status_flags(2) & libc::O_NONBLOCK == 0
    ));

    // Frames that would be drawn after the drain if the worker were not mute.
    sink.emit(&ProgressEvent::StageStarted {
        stage: Stage::Resources,
        total: Some(3),
    });
    sink.emit(&ProgressEvent::Progress {
        stage: Stage::Resources,
        done: 1,
        total: Some(3),
        current: Some(ItemRef {
            kind: ItemKind::File,
            id: "queued-after-the-stall".to_string(),
        }),
    });
    let t = Instant::now();
    let teardown = session.end(RunOutcome::Failed);
    say(&format!(
        "TEARDOWN {} {}",
        if teardown == Teardown::Abandoned {
            "Abandoned"
        } else {
            "Other"
        },
        t.elapsed().as_millis()
    ));

    // The run goes on: its stderr is a healthy pipe from here, but the blocked
    // progress write is parked on the pty. If the worker held `Stderr`'s lock,
    // nothing could print. (The redirect and the print run on a helper thread:
    // a defect shows as "false" here, not as a hung child.)
    let mut fds = [0i32; 2];
    // SAFETY: pipe(2) fills two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // SAFETY: dup2/close on descriptors this process owns.
        unsafe {
            libc::dup2(fds[1], 2);
            libc::close(fds[1]);
        }
        eprintln!("persistent-line");
        let _ = tx.send(());
    });
    let printed = rx.recv_timeout(Duration::from_millis(1500)).is_ok();
    say(&format!("EPRINTLN {printed}"));
    if printed {
        // SAFETY: `fds[0]` is the read end made above.
        let mut reader = unsafe { File::from_raw_fd(fds[0]) };
        set_nonblocking(fds[0], true);
        let mut got = [0u8; 64];
        let n = reader.read(&mut got).unwrap_or(0);
        say(&format!(
            "PIPE {}",
            String::from_utf8_lossy(&got[..n]).trim_end()
        ));
    }

    say("READY");
    wait_for_go();
    // The terminal drains now (the parent reads the master): the blocked write
    // lands and the worker leaves. Give it time to do anything else it would.
    std::thread::sleep(ms(600));
    drop(sink);
    // The surface's descriptor is closed again.
    say(&format!("FDS {} {}", before.len(), fd_count()));
    say("DONE");
}

fn child_healthy() {
    watchdog();
    let before = fd_count();
    let flags_before = status_flags(2);

    // A secret-referencing session creates no surface: no descriptor, no byte.
    {
        let opts = options(ms(500));
        let session = opts.begin(info(true));
        session.sink().emit(&ProgressEvent::StageStarted {
            stage: Stage::Connect,
            total: None,
        });
        std::thread::sleep(ms(50));
        say(&format!("SECRET_FDS {}", fd_count() - before));
        assert_eq!(session.end(RunOutcome::Completed), Teardown::Clean);
    }
    say("SECRET_BYTES_MARK");

    // Many healthy sessions: one private descriptor each, closed at the end.
    for i in 0..40 {
        let opts = options(ms(500));
        let session = opts.begin(info(false));
        session.sink().emit(&ProgressEvent::StageStarted {
            stage: Stage::Connect,
            total: None,
        });
        if i == 0 {
            std::thread::sleep(ms(50));
            say(&format!("SESSION_FDS {}", fd_count() - before));
        }
        assert_eq!(session.end(RunOutcome::Completed), Teardown::Clean);
    }
    say(&format!("FDS {before} {}", fd_count()));
    say(&format!(
        "STDERR_FLAGS_UNCHANGED {} ({flags_before:#x} -> {:#x})",
        status_flags(2) == flags_before,
        status_flags(2)
    ));
    say("DONE");
}

/// The stalled terminal for the production *plain* renderer: the same contract
/// as `child_stalled`, with lines instead of frames. The worker blocks writing
/// the run's first line; nothing queued behind it may follow once the terminal
/// drains.
fn child_stalled_plain() {
    watchdog();
    fill_stderr();
    let before = open_fds();
    let flags_before = status_flags(2);

    let opts = ProgressOptions::new(ProgressMode::Plain)
        .with_consumer_factory(stderr_plain_consumer_factory())
        .with_teardown_bound(ms(200));
    // `begin` emits `RunStarted`: the worker blocks in the kernel writing the
    // run's first line.
    let session = opts.begin(info(false));
    let sink = session.sink();
    std::thread::sleep(ms(200));
    say(&format!("NEWFDS {}", open_fds().len() - before.len()));
    say(&format!(
        "STDERR_FLAGS_UNCHANGED {}",
        status_flags(2) == flags_before && status_flags(2) & libc::O_NONBLOCK == 0
    ));
    sink.emit(&ProgressEvent::StageStarted {
        stage: Stage::Resources,
        total: Some(3),
    });
    sink.emit(&ProgressEvent::Progress {
        stage: Stage::Resources,
        done: 1,
        total: Some(3),
        current: Some(ItemRef {
            kind: ItemKind::File,
            id: "queued-after-the-stall".to_string(),
        }),
    });
    let t = Instant::now();
    let teardown = session.end(RunOutcome::Failed);
    say(&format!(
        "TEARDOWN {} {}",
        if teardown == Teardown::Abandoned {
            "Abandoned"
        } else {
            "Other"
        },
        t.elapsed().as_millis()
    ));
    // The run goes on: its stderr is a healthy pipe from here.
    let mut fds = [0i32; 2];
    // SAFETY: pipe(2) fills two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // SAFETY: dup2/close on descriptors this process owns.
        unsafe {
            libc::dup2(fds[1], 2);
            libc::close(fds[1]);
        }
        eprintln!("persistent-line");
        let _ = tx.send(());
    });
    say(&format!(
        "EPRINTLN {}",
        rx.recv_timeout(Duration::from_millis(1500)).is_ok()
    ));
    // The test's own pipe is not part of the descriptor accounting below.
    // SAFETY: `fds[0]` is the read end made above and is not used again.
    unsafe { libc::close(fds[0]) };
    say("READY");
    wait_for_go();
    std::thread::sleep(ms(600));
    drop(sink);
    say(&format!("FDS {} {}", before.len(), fd_count()));
    say("DONE");
}

/// RA-L1: the run panics with progress events still queued. The session is
/// dropped while the thread unwinds, which detaches its worker; the worker must
/// not draw what is queued (or erase) after the panic text.
///
/// The queued event is made deterministic by the renderer's own coalescing: the
/// first frame is written, and an event that follows within `MIN_REDRAW` (100 ms)
/// is held until that interval is over. The panic comes well before that, so a
/// worker that was not muted draws the held frame (and erases) after the panic
/// text, about 50 ms later. The panic hook prints the marker on the real
/// terminal, so everything after it on the wire is a late write.
fn child_panic() {
    watchdog();
    std::panic::set_hook(Box::new(|_| {
        eprintln!("{PANIC_MARK}");
    }));
    let opts = options(Duration::from_secs(5));
    let session = opts.begin(info(false));
    let sink = session.sink();
    sink.emit(&ProgressEvent::StageStarted {
        stage: Stage::Resources,
        total: Some(3),
    });
    // The first frame is on the wire (the worker draws a first event at once);
    // the held frame below must still arrive within the 100 ms coalescing
    // window of it, so this wait is kept short.
    std::thread::sleep(ms(20));
    sink.emit(&ProgressEvent::Progress {
        stage: Stage::Resources,
        done: 1,
        total: Some(3),
        current: Some(ItemRef {
            kind: ItemKind::File,
            id: "queued-before-the-panic".to_string(),
        }),
    });
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _session = session;
        panic!("the run panicked (expected by this test)");
    }));
    say(&format!("CAUGHT {}", caught.is_err()));
    // The detached worker has every chance to misbehave: its channel is still
    // open (`sink` is alive) and the held frame is due 100 ms after the first.
    std::thread::sleep(ms(600));
    drop(sink);
    std::thread::sleep(ms(100));
    say("DONE");
}

/// Entry point of the re-executed children; a no-op in a normal test run.
#[test]
fn child_entry() {
    match std::env::var(MODE_VAR).as_deref() {
        Ok("stalled") => child_stalled(),
        Ok("healthy") => child_healthy(),
        Ok("panic") => child_panic(),
        Ok("stalled_plain") => child_stalled_plain(),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// parent side
// ---------------------------------------------------------------------------

struct Pty {
    master: File,
    slave: File,
}

impl Pty {
    fn open() -> Pty {
        let (mut m, mut s) = (0i32, 0i32);
        let mut ws = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty fills two descriptors; the pointers are live locals.
        let rc = unsafe {
            libc::openpty(
                &mut m,
                &mut s,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut ws,
            )
        };
        assert_eq!(rc, 0, "openpty");
        // SAFETY: both descriptors are fresh and owned here.
        unsafe {
            Pty {
                master: File::from_raw_fd(m),
                slave: File::from_raw_fd(s),
            }
        }
    }
}

struct Child {
    process: std::process::Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
    master: File,
}

fn spawn(mode: &str) -> Child {
    let pty = Pty::open();
    let mut process = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env(MODE_VAR, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(pty.slave))
        .spawn()
        .unwrap();
    let stdout = process.stdout.take().unwrap();
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    Child {
        process,
        lines,
        seen: Vec::new(),
        master: pty.master,
    }
}

impl Child {
    /// Read the child's facts up to and including the line starting `until`.
    fn until(&mut self, until: &str) {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    // libtest's own "test x ... " may precede the fact on its line.
                    let Some((_, fact)) = line.split_once("STALL:") else {
                        continue;
                    };
                    assert!(
                        !fact.starts_with("FAIL"),
                        "child: {fact}; saw {:?}",
                        self.seen
                    );
                    self.seen.push(fact.to_string());
                    if fact.starts_with(until) {
                        return;
                    }
                }
                Err(_) => {
                    let _ = self.process.kill();
                    panic!("child never said {until:?}; saw {:?}", self.seen);
                }
            }
        }
    }

    fn fact(&self, prefix: &str) -> &str {
        self.seen
            .iter()
            .find(|f| f.starts_with(prefix))
            .unwrap_or_else(|| panic!("no {prefix:?} in {:?}", self.seen))
            .strip_prefix(prefix)
            .unwrap()
            .trim()
    }

    fn go(&mut self) {
        let stdin = self.process.stdin.as_mut().unwrap();
        writeln!(stdin, "go").unwrap();
        stdin.flush().unwrap();
    }

    /// Everything the terminal receives from now until the child is gone.
    fn drain_until_exit(&mut self) -> Vec<u8> {
        let master = self.master.try_clone().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut master = master;
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = master.read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            let _ = tx.send(out);
        });
        self.until("DONE");
        let status = self.process.wait().unwrap();
        assert!(status.success(), "child status {status:?}");
        rx.recv_timeout(Duration::from_secs(10)).unwrap_or_default()
    }
}

#[test]
fn a_stalled_terminal_blocks_only_the_progress_worker() {
    let mut child = spawn("stalled");
    child.until("READY");

    // Teardown is bounded: about the 200 ms bound, nowhere near a hang.
    let mut parts = child.fact("TEARDOWN").split(' ');
    assert_eq!(parts.next(), Some("Abandoned"), "{:?}", child.seen);
    let took: u64 = parts.next().unwrap().parse().unwrap();
    assert!((200..1500).contains(&took), "teardown took {took} ms");

    // The main thread still prints, with the worker parked in a blocked write.
    assert_eq!(
        child.fact("EPRINTLN"),
        "true",
        "the main thread's stderr is held up by the progress worker: {:?}",
        child.seen
    );
    assert_eq!(child.fact("PIPE"), "persistent-line");

    // The surface's descriptor is private and blocking; stderr's flags are not
    // touched by it (a shared O_NONBLOCK would change `eprintln!` too).
    assert_eq!(child.fact("NEWFDS"), "1", "{:?}", child.seen);
    assert_eq!(child.fact("NEWFD_NONBLOCK"), "false");
    assert_eq!(child.fact("STDERR_FLAGS_UNCHANGED"), "true");

    // Now the terminal drains. Only the frame whose write was already blocked
    // arrives: no queued frame (`apply`, `resources`), no erase after it.
    child.go();
    let bytes = child.drain_until_exit();
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(
        text.ends_with(&format!("{CLEAR}connect")),
        "the blocked frame is the last thing on the terminal: {:?}",
        &text[text.len().saturating_sub(120)..]
    );
    assert_eq!(
        text.matches(CLEAR).count(),
        1,
        "exactly one transient write"
    );
    assert!(!text.contains("queued-after-the-stall"));
    assert!(!text.contains("apply"));

    // And the descriptor is gone again.
    let fds: Vec<usize> = child
        .fact("FDS")
        .split(' ')
        .map(|n| n.parse().unwrap())
        .collect();
    assert_eq!(fds[0], fds[1], "descriptor leak: {fds:?}");
}

#[test]
fn the_private_descriptor_is_closed_blocking_and_absent_for_secrets() {
    let mut child = spawn("healthy");
    child.until("SESSION_FDS");
    let bytes = child.drain_until_exit();

    assert_eq!(child.fact("SECRET_FDS"), "0", "no surface for a secret run");
    assert_eq!(child.fact("SESSION_FDS"), "1", "one private descriptor");
    let fds: Vec<usize> = child
        .fact("FDS")
        .split(' ')
        .map(|n| n.parse().unwrap())
        .collect();
    assert_eq!(fds[0], fds[1], "descriptor leak over 40 sessions: {fds:?}");
    assert!(
        child.fact("STDERR_FLAGS_UNCHANGED").starts_with("true"),
        "{:?}",
        child.seen
    );

    // 40 healthy sessions drew `connect` and erased it; the secret one wrote
    // nothing at all (the terminal starts with a frame, not an erase).
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(text.starts_with(&format!("{CLEAR}connect")), "{text:?}");
    assert_eq!(text.matches(&format!("{CLEAR}connect")).count(), 40);
    assert!(text.ends_with(CLEAR));
}

/// RA-L1 on a real terminal, through the production consumer: after a panic
/// unwinds out of a run that still had progress queued, the detached worker
/// writes nothing, no queued frame and no erase. Before the fix the terminal
/// received the held frame and an erase after the panic text (the re-audit saw
/// `CLEAR` five times where one is right).
#[test]
fn a_panic_unwind_leaves_no_progress_bytes_after_the_panic_text() {
    let mut child = spawn("panic");
    let bytes = child.drain_until_exit();
    assert_eq!(child.fact("CAUGHT"), "true", "{:?}", child.seen);
    let text = String::from_utf8_lossy(&bytes).to_string();

    // Positive control: the renderer was alive and drew its first frame before
    // the panic.
    let (before, after) = text
        .split_once(PANIC_MARK)
        .unwrap_or_else(|| panic!("the panic hook's marker never reached the terminal: {text:?}"));
    assert!(
        before.contains(&format!("{CLEAR}apply 0/3")),
        "the first frame should precede the panic: {before:?}"
    );

    // The panic text is the last thing on the terminal: only the line end that
    // the hook's own `eprintln!` wrote follows its marker.
    assert_eq!(
        after, "\r\n",
        "a detached progress worker wrote after the panic text: {after:?}"
    );
    // (No count of frames before the marker is asserted: on a machine so slow
    // that the second event was drawn before the panic, there is simply nothing
    // left to be late, and the check above still holds.)
}

/// S5: a stalled terminal and the production plain renderer. Teardown is bounded,
/// the main thread's stderr is independent of the blocked write, the descriptor
/// is private and blocking, and once the terminal drains only the one line whose
/// write was already blocked arrives: no queued line, no run-end line.
#[test]
fn a_stalled_terminal_blocks_only_the_plain_progress_worker() {
    let mut child = spawn("stalled_plain");
    child.until("READY");
    let mut parts = child.fact("TEARDOWN").split(' ');
    assert_eq!(parts.next(), Some("Abandoned"), "{:?}", child.seen);
    let took: u64 = parts.next().unwrap().parse().unwrap();
    assert!((200..1500).contains(&took), "teardown took {took} ms");
    assert_eq!(
        child.fact("EPRINTLN"),
        "true",
        "the main thread's stderr is held up by the plain progress worker: {:?}",
        child.seen
    );
    assert_eq!(child.fact("NEWFDS"), "1", "{:?}", child.seen);
    assert_eq!(child.fact("STDERR_FLAGS_UNCHANGED"), "true");

    child.go();
    let bytes = child.drain_until_exit();
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(
        text.ends_with("progress: run: apply started\r\n"),
        "the blocked line is the last thing on the terminal: {:?}",
        &text[text.len().saturating_sub(120)..]
    );
    assert_eq!(text.matches("progress:").count(), 1, "{text:?}");
    assert!(!text.contains("queued-after-the-stall"));
    assert!(!text.contains("run: apply failed"));
    assert!(
        !text.contains('\x1b'),
        "plain progress never writes an escape"
    );
    let fds: Vec<usize> = child
        .fact("FDS")
        .split(' ')
        .map(|n| n.parse().unwrap())
        .collect();
    assert_eq!(fds[0], fds[1], "descriptor leak: {fds:?}");
}
