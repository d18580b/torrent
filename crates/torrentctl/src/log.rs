//! torrentctl's log: a file in the XDG state directory, never the terminal
//! the UI owns, rotated by size so it stays bounded, and the panics that
//! end a session written into it.

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

/// The live log's file name; rotated files add `.1` (the newest) up to
/// `.`[`KEEP`].
pub const FILE_NAME: &str = "torrentctl.log";

/// The size past which the live log is rotated.
pub const MAX_BYTES: u64 = 10 * 1024 * 1024;

/// How many rotated files are kept beside the live one; the oldest goes.
pub const KEEP: usize = 4;

/// The environment variable that picks the log's line format.
pub const FORMAT_VAR: &str = "TORRENTCTL_LOG_FORMAT";

/// How each log line is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// `tracing`'s human-readable lines: the default.
    Text,
    /// One JSON object per line.
    Json,
}

impl Format {
    /// The format `TORRENTCTL_LOG_FORMAT`'s value names: `json`, or `text`
    /// when it is unset or empty. Any other value is returned as the error,
    /// and the caller logs it and writes text.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim) {
            None | Some("" | "text") => Ok(Self::Text),
            Some("json") => Ok(Self::Json),
            Some(other) => Err(other.to_owned()),
        }
    }
}

/// A log file that rotates by size: once a line would take it past
/// `max_bytes`, `name` becomes `name.1`, `name.1` becomes `name.2`, and so on
/// up to `name.<keep>`, whose previous contents are dropped.
///
/// It never fails a write. `tracing_appender`'s worker reports a failed
/// write with `eprintln!`, onto the terminal the UI owns, so a rotation that
/// cannot rename goes on appending to the live file and tries again on the
/// next line, and a line with no file to go to is dropped.
#[derive(Debug)]
pub struct SizeRotating {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: Option<File>,
    written: u64,
}

impl SizeRotating {
    /// Open (or create) `dir/name` for appending. Fails only where the file
    /// cannot be opened: that is the failure the caller reports.
    pub fn open(dir: &Path, name: &str, max_bytes: u64, keep: usize) -> io::Result<Self> {
        let path = dir.join(name);
        let file = append(&path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            path,
            max_bytes,
            keep,
            file: Some(file),
            written,
        })
    }

    /// `name.<n>`, or the live file for 0.
    fn numbered(&self, n: usize) -> PathBuf {
        if n == 0 {
            return self.path.clone();
        }
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    /// Shift every file one number up, dropping the oldest, and start a new
    /// live file. A file that is missing, the live one included (deleted
    /// while open), is skipped rather than failing the rotation: a failure
    /// would leave the shifted files shifted and retry on the next line,
    /// shifting them again until all but one is gone.
    fn rotate(&mut self) -> io::Result<()> {
        if self.keep == 0 {
            match std::fs::remove_file(&self.path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                other => other?,
            }
        } else {
            for n in (0..self.keep).rev() {
                match std::fs::rename(self.numbered(n), self.numbered(n + 1)) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    other => other?,
                }
            }
        }
        self.file = None;
        self.written = 0;
        self.file = Some(append(&self.path)?);
        Ok(())
    }
}

fn append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

impl Write for SizeRotating {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if self.file.is_none() {
            // A rotation renamed the live file but could not start a new one.
            self.file = append(&self.path).ok();
        } else if self.written > 0 && self.written.saturating_add(len) > self.max_bytes {
            // ignore-result: see the type's docs; the next line tries again.
            let _ = self.rotate();
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(buf.len());
        };
        match file.write(buf) {
            Ok(n) => {
                self.written = self
                    .written
                    .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                Ok(n)
            }
            Err(_) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            // ignore-result: see the type's docs.
            let _ = file.flush();
        }
        Ok(())
    }
}

/// Where the log goes: `$XDG_STATE_HOME/torrentctl`.
fn dir() -> Result<PathBuf, String> {
    use etcetera::BaseStrategy as _;
    let strategy = etcetera::choose_base_strategy()
        .map_err(|e| format!("no home directory to keep it in: {e}"))?;
    let state = strategy
        .state_dir()
        .ok_or_else(|| "this platform has no state directory".to_owned())?;
    Ok(state.join("torrentctl"))
}

/// Start logging to [`FILE_NAME`] in the state directory, in the format
/// [`FORMAT_VAR`] names, filtered by `TORRENTCTL_LOG` (default `info`).
/// Returns the guard that flushes it, or why there is no log, which the
/// caller prints once the terminal is the user's again.
pub fn init() -> Result<tracing_appender::non_blocking::WorkerGuard, String> {
    let dir = dir().map_err(|e| format!("torrentctl: logging is off: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "torrentctl: logging is off: cannot create {}: {e}",
            dir.display()
        )
    })?;
    let file = SizeRotating::open(&dir, FILE_NAME, MAX_BYTES, KEEP).map_err(|e| {
        format!(
            "torrentctl: logging is off: cannot open {}: {e}",
            dir.join(FILE_NAME).display()
        )
    })?;
    let (writer, guard) = tracing_appender::non_blocking(file);
    let filter = tracing_subscriber::EnvFilter::try_from_env("TORRENTCTL_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let format = Format::parse(std::env::var(FORMAT_VAR).ok().as_deref());
    let builder = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_env_filter(filter);
    match format {
        Ok(Format::Json) => builder.json().init(),
        Ok(Format::Text) | Err(_) => builder.init(),
    }
    if let Err(value) = format {
        tracing::warn!(
            target: "torrentctl",
            value,
            "{FORMAT_VAR} is neither text nor json; writing text"
        );
    }
    Ok(guard)
}

/// Write a panic, with a backtrace captured whatever `RUST_BACKTRACE` says,
/// to the log. Installed in front of the hook that restores the terminal, so
/// the report is in the log before anything else happens.
pub fn panicked(info: &std::panic::PanicHookInfo<'_>) {
    let backtrace = std::backtrace::Backtrace::force_capture();
    let thread = std::thread::current();
    tracing::error!(
        target: "torrentctl::panic",
        thread = thread.name().unwrap_or("<unnamed>"),
        backtrace = %backtrace,
        "panicked: {info}"
    );
}

/// Put [`panicked`] in front of the panic hook installed now.
pub fn log_panics() {
    let next = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        panicked(info);
        next(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn the_format_is_text_unless_json_is_asked_for() {
        assert_eq!(Format::parse(None), Ok(Format::Text));
        assert_eq!(Format::parse(Some("")), Ok(Format::Text));
        assert_eq!(Format::parse(Some("text")), Ok(Format::Text));
        assert_eq!(Format::parse(Some("json")), Ok(Format::Json));
        assert_eq!(Format::parse(Some("yaml")), Err("yaml".to_owned()));
    }

    #[test]
    fn the_log_rotates_by_size_and_keeps_a_bounded_number_of_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = SizeRotating::open(dir.path(), "t.log", 10, 2).unwrap();
        for line in ["aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }
        log.flush().unwrap();
        assert_eq!(read(&dir.path().join("t.log")), "dddddddd\n");
        assert_eq!(read(&dir.path().join("t.log.1")), "cccccccc\n");
        assert_eq!(read(&dir.path().join("t.log.2")), "bbbbbbbb\n");
        assert!(
            !dir.path().join("t.log.3").exists(),
            "the oldest is dropped"
        );
        let names = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(names, 3, "the live file and two rotated ones");
    }

    #[test]
    fn a_log_reopened_counts_what_it_already_holds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t.log"), "from the last run\n").unwrap();
        let mut log = SizeRotating::open(dir.path(), "t.log", 20, 1).unwrap();
        log.write_all(b"new line\n").unwrap();
        assert_eq!(read(&dir.path().join("t.log")), "new line\n");
        assert_eq!(read(&dir.path().join("t.log.1")), "from the last run\n");
    }

    #[test]
    fn a_line_longer_than_the_limit_is_still_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = SizeRotating::open(dir.path(), "t.log", 4, 1).unwrap();
        log.write_all(b"longer than four\n").unwrap();
        assert_eq!(read(&dir.path().join("t.log")), "longer than four\n");
        assert!(
            !dir.path().join("t.log.1").exists(),
            "an empty file is not rotated"
        );
    }

    #[test]
    fn a_rotation_that_cannot_rename_keeps_appending_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = SizeRotating::open(dir.path(), "t.log", 4, 1).unwrap();
        log.write_all(b"first\n").unwrap();
        // A directory where `t.log.1` would go: the rename onto it fails.
        std::fs::create_dir(dir.path().join("t.log.1")).unwrap();
        std::fs::write(dir.path().join("t.log.1/x"), "").unwrap();
        log.write_all(b"second\n").unwrap();
        assert_eq!(read(&dir.path().join("t.log")), "first\nsecond\n");
    }

    #[test]
    fn a_live_log_deleted_while_open_is_replaced_without_losing_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = SizeRotating::open(dir.path(), "t.log", 10, 2).unwrap();
        log.write_all(b"aaaaaaaa\n").unwrap();
        log.write_all(b"bbbbbbbb\n").unwrap();
        std::fs::remove_file(dir.path().join("t.log")).unwrap();
        for line in ["cccccccc\n", "dddddddd\n", "eeeeeeee\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }
        assert_eq!(read(&dir.path().join("t.log")), "eeeeeeee\n");
        assert_eq!(read(&dir.path().join("t.log.1")), "dddddddd\n");
        assert_eq!(read(&dir.path().join("t.log.2")), "cccccccc\n");
    }

    #[test]
    fn a_log_that_cannot_be_opened_says_so() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("t.log")).unwrap();
        assert!(SizeRotating::open(dir.path(), "t.log", 10, 1).is_err());
    }
}
