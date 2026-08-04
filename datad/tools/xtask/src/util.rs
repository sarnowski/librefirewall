//! Process and filesystem plumbing shared by every stage of the orchestrator.
//!
//! Every failure the build can hit is one of three kinds, and [`Error`] names
//! them so the operator gets a cause rather than a sentence: an external tool
//! failed, a filesystem operation failed, or a validated input is wrong.
//!
//! The build drives a dozen external tools whose own diagnostics are the only
//! clue to what broke. [`run_command`] therefore captures the child's stderr
//! *while* streaming it on — a build must keep showing live progress — and
//! folds the full command line plus that stderr into a [`CommandError`]. An
//! exit status alone says a step failed but never why, which is the difference
//! between an actionable build failure and a guessing game.
//!
//! The capture is bounded ([`STDERR_CAPTURE_LIMIT`], tail-biased because a
//! tool's real diagnostic sits at the end of its output) so a runaway child
//! cannot grow the orchestrator's memory without limit.

use std::{
    error, fmt, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
};

/// Upper bound on the child stderr retained for an error message. A failing
/// tool's actionable diagnostic sits at the *end* of its output, so the tail is
/// kept and the head dropped once the limit is reached.
const STDERR_CAPTURE_LIMIT: usize = 64 * 1024;

/// A build-step failure, carrying enough context to act on without re-running
/// the build by hand.
#[derive(Debug)]
pub(crate) enum Error {
    /// An external tool failed to start, or exited non-zero.
    Command(CommandError),
    /// A filesystem operation failed.
    Io {
        /// What the build was doing, e.g. `create`, `read`, `copy`.
        action: String,
        /// The path the action was applied to.
        path: PathBuf,
        /// The underlying failure.
        source: io::Error,
    },
    /// An input the build validates — a pin, a version, a signature, a size —
    /// did not hold. This is a rejected input, never an internal invariant
    /// violation; those panic.
    Invalid(String),
}

impl Error {
    /// Tag an [`io::Error`] with the action and path that produced it.
    pub(crate) fn io(action: &str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action: action.to_owned(),
            path: path.to_path_buf(),
            source,
        }
    }

    /// A validated input did not hold.
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} {}: {source}", path.display()),
            Self::Invalid(message) => write!(formatter, "{message}"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Command(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::Invalid(_) => None,
        }
    }
}

impl From<CommandError> for Error {
    fn from(error: CommandError) -> Self {
        Self::Command(error)
    }
}

/// Flatten an [`Error`] for the stages that still thread `String` failures.
/// The rendered form keeps the command line and the captured stderr, so nothing
/// an operator needs is lost across that boundary.
impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.to_string()
    }
}

/// An external tool that failed to start, or ran and exited non-zero.
///
/// Carries the full command line and the child's captured stderr, which is what
/// makes a build failure diagnosable without reproducing it by hand.
#[derive(Debug)]
pub(crate) struct CommandError {
    description: String,
    command_line: String,
    failure: CommandFailure,
}

#[derive(Debug)]
enum CommandFailure {
    Spawn(io::Error),
    Exit { status: ExitStatus, stderr: String },
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: ", self.description)?;
        match &self.failure {
            CommandFailure::Spawn(source) => {
                write!(formatter, "could not run `{}`: {source}", self.command_line)
            }
            CommandFailure::Exit { status, stderr } => {
                write!(formatter, "`{}` {status}", self.command_line)?;
                if stderr.is_empty() {
                    Ok(())
                } else {
                    write!(formatter, "\n--- stderr ---\n{stderr}\n--------------")
                }
            }
        }
    }
}

impl error::Error for CommandError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.failure {
            CommandFailure::Spawn(source) => Some(source),
            CommandFailure::Exit { .. } => None,
        }
    }
}

/// Resolve the Cargo workspace root from this crate's compile-time manifest
/// dir (`tools/xtask` → two levels up). Every build path is anchored here;
/// only the documentation book lives outside it, one level further up.
pub(crate) fn workspace_root() -> Result<PathBuf, Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| Error::invalid("cannot determine workspace root"))
}

/// Resolve the repository root: the workspace root's parent.
///
/// The two differ because the repository holds more than this Cargo
/// workspace: the workspace is one component directory below the root, while
/// the documentation book — which the gate reads as data — sits at the root
/// and covers every component.
pub(crate) fn repository_root() -> Result<PathBuf, Error> {
    workspace_root()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| Error::invalid("cannot determine repository root"))
}

/// Run an external command to completion, failing on a non-zero exit.
///
/// The child's stdout stays inherited (live build progress) while its stderr is
/// streamed on *and* captured, so the failure carries the tool's own
/// diagnostic. `description` names the build step and heads the error message.
pub(crate) fn run_command(command: &mut Command, description: &str) -> Result<(), Error> {
    let command_line = render_command_line(command);
    let mut child = match command.stderr(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(source) => return Err(spawn_error(description, command_line, source)),
    };

    // Drain stderr on a worker so the child can never block on a full pipe
    // while the parent waits for it to exit.
    let stderr = child.stderr.take().expect("stderr was piped above");
    let drain = thread::spawn(move || tee_stderr(stderr));

    let status = match child.wait() {
        Ok(status) => status,
        Err(source) => return Err(spawn_error(description, command_line, source)),
    };
    let captured = drain.join().unwrap_or_default();

    if status.success() {
        Ok(())
    } else {
        Err(Error::Command(CommandError {
            description: description.to_owned(),
            command_line,
            failure: CommandFailure::Exit {
                status,
                stderr: captured,
            },
        }))
    }
}

/// Run an external command and return its stdout, failing on a non-zero exit.
///
/// Used where the tool's output *is* the result — a gpg status stream, a
/// checksum listing — rather than progress for the operator. Stderr is replayed
/// for the operator and captured into the error exactly as in [`run_command`].
pub(crate) fn capture_stdout(command: &mut Command, description: &str) -> Result<String, Error> {
    let command_line = render_command_line(command);
    let output = match command.stderr(Stdio::piped()).output() {
        Ok(output) => output,
        Err(source) => return Err(spawn_error(description, command_line, source)),
    };
    // `output()` swallows stderr, so replay it before judging the exit status.
    io::stderr().write_all(&output.stderr).ok();
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(Error::Command(CommandError {
            description: description.to_owned(),
            command_line,
            failure: CommandFailure::Exit {
                status: output.status,
                stderr: tail(String::from_utf8_lossy(&output.stderr).trim()),
            },
        }))
    }
}

fn spawn_error(description: &str, command_line: String, source: io::Error) -> Error {
    Error::Command(CommandError {
        description: description.to_owned(),
        command_line,
        failure: CommandFailure::Spawn(source),
    })
}

/// Copy the child's stderr onto ours as it arrives and keep the tail for the
/// error message. Streaming matters for long builds; the bound matters because
/// the child's output volume is not something the orchestrator controls.
fn tee_stderr(mut stderr: impl Read) -> String {
    let mut captured: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut sink = io::stderr();
    while let Ok(read) = stderr.read(&mut chunk) {
        if read == 0 {
            break;
        }
        sink.write_all(&chunk[..read]).ok();
        append_bounded(&mut captured, &chunk[..read]);
    }
    sink.flush().ok();
    String::from_utf8_lossy(&captured).trim().to_owned()
}

/// Append `chunk` to `captured`, dropping from the front so the retained bytes
/// never exceed [`STDERR_CAPTURE_LIMIT`] and are always the most recent ones.
fn append_bounded(captured: &mut Vec<u8>, chunk: &[u8]) {
    captured.extend_from_slice(chunk);
    if captured.len() > STDERR_CAPTURE_LIMIT {
        captured.drain(..captured.len() - STDERR_CAPTURE_LIMIT);
    }
}

fn tail(text: &str) -> String {
    if text.len() <= STDERR_CAPTURE_LIMIT {
        return text.to_owned();
    }
    // Cut on a char boundary so the retained tail is still valid UTF-8.
    let mut start = text.len() - STDERR_CAPTURE_LIMIT;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_owned()
}

/// Render a command as a readable, unambiguous command line for diagnostics.
/// Arguments containing whitespace are quoted so an empty or spaced argument is
/// visible rather than silently merged with its neighbour — which is exactly
/// the kind of argument (an empty `--passphrase`, a spaced key UID) this build
/// hands to the tools whose failures matter most.
fn render_command_line(command: &Command) -> String {
    let mut line = command.get_program().to_string_lossy().into_owned();
    for argument in command.get_args() {
        let argument = argument.to_string_lossy();
        line.push(' ');
        if argument.is_empty() || argument.contains(char::is_whitespace) {
            line.push('\'');
            line.push_str(&argument);
            line.push('\'');
        } else {
            line.push_str(&argument);
        }
    }
    line
}

pub(crate) fn copy_file(source: &Path, destination: &Path) -> Result<(), Error> {
    require_file(source)?;
    fs::copy(source, destination).map_err(|error| Error::Io {
        action: format!("copy {} to", source.display()),
        path: destination.to_path_buf(),
        source: error,
    })?;
    Ok(())
}

pub(crate) fn require_file(path: &Path) -> Result<(), Error> {
    if path.is_file() {
        Ok(())
    } else {
        Err(Error::invalid(format!(
            "required file is missing: {}",
            path.display()
        )))
    }
}

pub(crate) fn recreate_dir(path: &Path) -> Result<(), Error> {
    if path.exists() {
        fs::remove_dir_all(path).map_err(|error| Error::io("remove", path, error))?;
    }
    fs::create_dir_all(path).map_err(|error| Error::io("create", path, error))
}

/// Return the first existing candidate path, or an error naming every candidate
/// that was tried.
pub(crate) fn locate(candidates: &[&str], description: &str) -> Result<PathBuf, Error> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| Error::invalid(format!("{description} not found in {candidates:?}")))
}

pub(crate) fn set_permissions_0700(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| Error::io("chmod 0700", path, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failing_command_reports_its_command_line_and_stderr() {
        let error = run_command(
            Command::new("sh").args(["-c", "echo boom >&2; exit 3"]),
            "provoke a failure",
        )
        .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("provoke a failure"), "got: {rendered}");
        assert!(rendered.contains("sh -c"), "got: {rendered}");
        assert!(rendered.contains("boom"), "got: {rendered}");
        assert!(
            error::Error::source(&error).is_some(),
            "a command failure exposes its cause"
        );
    }

    #[test]
    fn a_command_that_cannot_start_names_it() {
        let error = run_command(
            &mut Command::new("librefirewall-no-such-tool"),
            "run a missing tool",
        )
        .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("run a missing tool"), "got: {rendered}");
        assert!(
            rendered.contains("librefirewall-no-such-tool"),
            "got: {rendered}"
        );
        let command = error::Error::source(&error).expect("a command error");
        assert!(
            error::Error::source(command).is_some(),
            "the spawn failure is the root cause"
        );
    }

    #[test]
    fn capture_stdout_returns_output_and_reports_failures() {
        let out = capture_stdout(Command::new("sh").args(["-c", "printf hello"]), "echo").unwrap();
        assert_eq!(out, "hello");

        let error = capture_stdout(
            Command::new("sh").args(["-c", "echo nope >&2; exit 1"]),
            "failing echo",
        )
        .unwrap_err();
        assert!(error.to_string().contains("nope"), "got: {error}");
    }

    #[test]
    fn empty_and_spaced_arguments_stay_visible_in_the_rendered_line() {
        let mut command = Command::new("gpg");
        command.args(["--passphrase", "", "--comment", "a b"]);
        assert_eq!(
            render_command_line(&command),
            "gpg --passphrase '' --comment 'a b'"
        );
    }

    #[test]
    fn a_flood_of_child_stderr_is_bounded_and_keeps_the_most_recent_bytes() {
        // A child's output volume is not something the orchestrator controls,
        // and the actionable diagnostic is the last thing a tool prints.
        let mut captured = Vec::new();
        for _ in 0..(STDERR_CAPTURE_LIMIT / 1024) + 8 {
            append_bounded(&mut captured, &[b'x'; 1024]);
            assert!(captured.len() <= STDERR_CAPTURE_LIMIT);
        }
        append_bounded(&mut captured, b"FINAL_MARKER");
        assert_eq!(captured.len(), STDERR_CAPTURE_LIMIT);
        assert!(captured.ends_with(b"FINAL_MARKER"), "the tail is retained");
    }

    #[test]
    fn output_below_the_bound_is_kept_whole() {
        let mut captured = Vec::new();
        append_bounded(&mut captured, b"short diagnostic");
        assert_eq!(captured, b"short diagnostic");
    }

    #[test]
    fn io_errors_name_the_action_and_path() {
        let error = recreate_dir(Path::new("/proc/librefirewall-cannot-create")).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("create"), "got: {rendered}");
        assert!(
            rendered.contains("/proc/librefirewall-cannot-create"),
            "got: {rendered}"
        );
        assert!(
            error::Error::source(&error).is_some(),
            "the io cause is kept"
        );
    }

    #[test]
    fn a_rejected_input_has_no_underlying_cause() {
        let error = Error::invalid("pin mismatch");
        assert_eq!(error.to_string(), "pin mismatch");
        assert!(error::Error::source(&error).is_none());
    }

    #[test]
    fn flattening_to_a_string_keeps_the_diagnostic() {
        let error = run_command(
            Command::new("sh").args(["-c", "echo detail >&2; exit 1"]),
            "flatten me",
        )
        .unwrap_err();
        let flattened: String = error.into();
        assert!(flattened.contains("flatten me"), "got: {flattened}");
        assert!(flattened.contains("detail"), "got: {flattened}");
    }

    #[test]
    fn locate_names_every_candidate_it_tried() {
        let error = locate(&["/nonexistent/a", "/nonexistent/b"], "test firmware")
            .unwrap_err()
            .to_string();
        assert!(error.contains("test firmware"), "got: {error}");
        assert!(error.contains("/nonexistent/b"), "got: {error}");
    }

    #[test]
    fn require_file_rejects_a_missing_path() {
        assert!(require_file(Path::new("/nonexistent/file")).is_err());
    }
}
