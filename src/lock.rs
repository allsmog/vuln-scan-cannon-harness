//! Dependency-free cross-process advisory lock + atomic file writes.
//!
//! Cannon's persistent state (the ledger, the queue) is one shared file per
//! target. Two `cannon` processes — e.g. a `fire` finishing while you run
//! `findings sync` — would otherwise `load → mutate → save` over each other and
//! the second writer's `save` would clobber the first's. A reader could also
//! observe a half-written file mid-`write`.
//!
//! Two primitives close those windows:
//!   - [`FileLock`]: an exclusive, RAII-released lockfile (atomic `create_new`,
//!     spin-wait with timeout, stale-lock breaker) so the read-modify-write
//!     critical section runs single-writer.
//!   - [`write_atomic`]: write to a per-process temp file then `rename` into
//!     place, so a concurrent reader sees either the old or the new file whole,
//!     never a torn one.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Locks held longer than this are presumed orphaned (process crashed without
/// releasing) and broken. Generous: a salvo's final merge is quick, but a slow
/// disk shouldn't trip it.
const STALE_AFTER: Duration = Duration::from_secs(120);
/// Give up acquiring after this long rather than hang a CLI invocation forever.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(60);
const SPIN: Duration = Duration::from_millis(50);

/// An exclusive advisory lock backed by a lockfile. Released on drop.
pub struct FileLock {
    path: PathBuf,
}

impl FileLock {
    /// Acquire an exclusive lock at `path`, spinning until it's free, the stale
    /// timeout breaks an orphaned lock, or [`ACQUIRE_TIMEOUT`] elapses.
    pub fn acquire(path: PathBuf) -> std::io::Result<FileLock> {
        Self::acquire_with(path, STALE_AFTER, ACQUIRE_TIMEOUT)
    }

    /// Lower-level acquire with explicit stale/timeout budgets (so tests can use
    /// millisecond values instead of the two-minute production defaults).
    fn acquire_with(path: PathBuf, stale_after: Duration, acquire_timeout: Duration) -> std::io::Result<FileLock> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let start = Instant::now();
        loop {
            // `create_new` maps to O_EXCL / CREATE_NEW: atomic "create iff absent"
            // across processes on Unix and Windows.
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    let _ = writeln!(f, "pid={}", std::process::id());
                    return Ok(FileLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Self::is_stale(&path, stale_after) {
                        // Best-effort break; a racing winner just re-loops.
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if start.elapsed() >= acquire_timeout {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("timed out acquiring lock {}", path.display()),
                        ));
                    }
                    std::thread::sleep(SPIN.min(acquire_timeout / 4 + Duration::from_millis(1)));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn is_stale(path: &Path, stale_after: Duration) -> bool {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .map(|t| t.elapsed().map(|age| age > stale_after).unwrap_or(false))
            .unwrap_or(false)
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Write `bytes` to `path` atomically: a unique temp file in the same directory
/// then `rename` over the destination (atomic on the same filesystem). The temp
/// name carries the pid so two processes never share a temp path.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let fname = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "out".into());
    let tmp = dir.join(format!(".{fname}.tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cannon-lock-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn lock_is_exclusive_then_released_on_drop() {
        let dir = tmp("excl");
        let lp = dir.join(".lock");
        let held = FileLock::acquire(lp.clone()).unwrap();
        // A second acquire while held must not succeed immediately…
        assert!(lp.exists());
        drop(held);
        // …and after drop the lockfile is gone and re-acquire works.
        assert!(!lp.exists());
        let again = FileLock::acquire(lp.clone()).unwrap();
        drop(again);
    }

    #[test]
    fn second_acquire_blocks_until_first_released() {
        use std::sync::mpsc;
        use std::thread;
        let dir = tmp("contend");
        let lp = dir.join(".lock");
        let held = FileLock::acquire(lp.clone()).unwrap();

        // A second acquirer in another thread must block while we hold it.
        let (tx, rx) = mpsc::channel();
        let lp2 = lp.clone();
        let t = thread::spawn(move || {
            let l = FileLock::acquire(lp2).unwrap(); // should only succeed after release
            tx.send(()).unwrap();
            drop(l);
        });
        // Give the contender time to spin; it must NOT have acquired yet.
        thread::sleep(Duration::from_millis(120));
        assert!(rx.try_recv().is_err(), "second acquire succeeded while lock was held");
        // Release; now the contender should acquire promptly.
        drop(held);
        rx.recv_timeout(Duration::from_secs(5)).expect("contender never acquired after release");
        t.join().unwrap();
    }

    #[test]
    fn acquire_times_out_when_held() {
        let dir = tmp("timeout");
        let lp = dir.join(".lock");
        let _held = FileLock::acquire(lp.clone()).unwrap();
        // Tiny stale + timeout budgets: a still-fresh held lock should time out.
        let r = FileLock::acquire_with(lp.clone(), Duration::from_secs(60), Duration::from_millis(150));
        assert!(r.is_err(), "acquire should time out while the lock is held fresh");
        assert_eq!(r.err().unwrap().kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn stale_lock_is_broken() {
        let dir = tmp("stale");
        let lp = dir.join(".lock");
        let _held = FileLock::acquire(lp.clone()).unwrap();
        // With a near-zero stale window, the existing lock is "orphaned" and gets
        // broken, so a contender acquires despite the file existing.
        std::thread::sleep(Duration::from_millis(20));
        let got = FileLock::acquire_with(lp.clone(), Duration::from_millis(1), Duration::from_secs(2));
        assert!(got.is_ok(), "a stale lock must be broken and re-acquired");
    }

    #[test]
    fn atomic_write_replaces_whole_file() {
        let dir = tmp("atomic");
        let f = dir.join("ledger.json");
        write_atomic(&f, b"first").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"first");
        write_atomic(&f, b"second").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"second");
        // No temp turds left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains(".tmp.")).collect();
        assert!(leftovers.is_empty(), "temp files leaked: {leftovers:?}");
    }
}
