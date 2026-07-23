//! QEMU virtio-net system harness.
//!
//! Boots the seL4/Microkit x86_64 image in QEMU with a single `virtio-net-pci`
//! NIC whose backend is a host-controlled TCP socket, injects one Ethernet
//! frame into the guest, captures the guest serial output, and asserts that the
//! forwarding success marker appears before a timeout.
//!
//! This module is intentionally self-contained: it duplicates the small process
//! and capture helpers from `main.rs` rather than depending on its private
//! items, so it can be dropped into the `xtask` binary with a single
//! `mod nic_harness;`.

use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Serial marker the guest emits once it has received and forwarded the frame.
const NIC_PASS_MARKER: &str = "LIBREFIREWALL_NIC_PASS:virtio-rx-frame-forwarded";

/// Total wall-clock budget from QEMU launch to marker. TCG (no KVM) boot of
/// seL4 plus a polling virtio driver is slow, hence the generous ceiling.
const NIC_TEST_TIMEOUT: Duration = Duration::from_secs(90);

/// How long to wait for QEMU to dial back into our listener before giving up.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);

/// Cadence of re-injection. virtio-net silently drops received frames while the
/// guest driver has not yet posted RX buffers, so a single early frame can be
/// lost; we resend until the guest reacts or the test times out.
const REINJECT_INTERVAL: Duration = Duration::from_millis(500);

/// Minimum Ethernet frame size on the wire without FCS.
const MIN_ETHERNET_FRAME: usize = 60;

/// Boot the image in QEMU, inject a broadcast frame over a virtio NIC, and
/// assert the guest reports it forwarded the frame.
///
/// `kernel` is the 32-bit seL4 kernel ELF (`sel4_32.elf`) loaded as the
/// Multiboot2 payload; `system` is the Microkit loader image (`loader.img`)
/// loaded as the initrd. The captured serial output is always written to
/// `log_path` (whose parent directories are created), whether the test passes
/// or fails, and QEMU is always killed and reaped on every exit path.
pub fn run_nic_test(
    root: &Path,
    kernel: &Path,
    system: &Path,
    log_path: &Path,
) -> Result<(), String> {
    require_file(kernel)?;
    require_file(system)?;

    // Ephemeral loopback port; QEMU's `connect=` backend dials in to us.
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("bind harness listener: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("read listener port: {error}"))?
        .port();
    // Non-blocking accept lets the timeout loop keep draining serial output
    // while it waits for QEMU to connect.
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set listener non-blocking: {error}"))?;

    let mut command = Command::new("qemu-system-x86_64");
    command
        .current_dir(root)
        .args(["-machine", "q35", "-accel", "tcg"])
        .args(["-cpu", "qemu64,+fsgsbase,+pdpe1gb,+xsaveopt,+xsave"])
        .args(["-m", "1G", "-display", "none", "-serial", "stdio"])
        .arg("-kernel")
        .arg(kernel)
        .arg("-initrd")
        .arg(system)
        .arg("-netdev")
        .arg(format!("socket,id=n0,connect=127.0.0.1:{port}"))
        .arg("-device")
        .arg(
            "virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off,\
             mac=52:54:00:12:34:56,bus=pcie.0,addr=02.0",
        )
        .arg("-no-reboot")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("start QEMU: {error}"))?;

    // Serial output arrives on both pipes; reader threads funnel it into a
    // single channel the timeout loop drains.
    let (sender, receiver) = mpsc::channel();
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate(&mut child, "stdout capture failure")?;
            return Err("capture QEMU stdout".to_owned());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate(&mut child, "stderr capture failure")?;
            return Err("capture QEMU stderr".to_owned());
        }
    };
    let stdout_reader = spawn_reader(stdout, sender.clone());
    let stderr_reader = spawn_reader(stderr, sender);

    let start = Instant::now();
    let mut output: Vec<u8> = Vec::new();
    // Kept alive across finalisation so it can be joined after QEMU dies.
    let mut socket_reader: Option<JoinHandle<io::Result<()>>> = None;

    let outcome: Result<(), String> = 'run: {
        // Phase 1: accept QEMU's socket dial-in.
        let stream = loop {
            drain(&receiver, &mut output);
            match listener.accept() {
                Ok((stream, _peer)) => break stream,
                Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => break 'run Err(format!("accept QEMU NIC socket: {error}")),
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    break 'run Err(format!(
                        "QEMU exited before connecting its NIC socket ({status})"
                    ));
                }
                Ok(None) => {}
                Err(error) => break 'run Err(format!("poll QEMU: {error}")),
            }
            if start.elapsed() >= ACCEPT_TIMEOUT {
                break 'run Err(format!(
                    "QEMU did not connect its NIC socket within {}s",
                    ACCEPT_TIMEOUT.as_secs()
                ));
            }
            thread::sleep(Duration::from_millis(25));
        };

        // Guarantee blocking semantics for the (dup'd) socket handles.
        if let Err(error) = stream.set_nonblocking(false) {
            break 'run Err(format!("set NIC socket blocking: {error}"));
        }

        // QEMU's `net_socket` STREAM backend frames every Ethernet frame as a
        // 4-byte big-endian length header followed by the raw L2 bytes (no FCS),
        // in both directions. We must drain the guest's TX so QEMU's TX ring
        // never blocks and stalls the guest; a dedicated reader discards it.
        let read_half = match stream.try_clone() {
            Ok(handle) => handle,
            Err(error) => break 'run Err(format!("clone NIC socket: {error}")),
        };
        socket_reader = Some(spawn_socket_drain(read_half));

        let mut writer = stream;
        let frame = build_injection_frame();
        let wire = encode_wire(&frame);

        // Inject immediately; the driver may not be ready yet, which is exactly
        // why we also re-inject on a fixed cadence below.
        if let Err(error) = writer.write_all(&wire) {
            break 'run Err(format!("inject first frame: {error}"));
        }
        let mut injecting = true;
        let mut last_injection = Instant::now();

        // Phase 2: watch for the pass marker, re-injecting periodically.
        loop {
            drain(&receiver, &mut output);
            if count_occurrences(&output, NIC_PASS_MARKER.as_bytes()) > 0 {
                break 'run Ok(());
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    break 'run Err(format!(
                        "QEMU exited before the NIC pass marker appeared ({status}); see {}",
                        log_path.display()
                    ));
                }
                Ok(None) => {}
                Err(error) => break 'run Err(format!("poll QEMU: {error}")),
            }
            if start.elapsed() >= NIC_TEST_TIMEOUT {
                break 'run Err(format!(
                    "timed out after {}s waiting for the NIC pass marker; see {}",
                    NIC_TEST_TIMEOUT.as_secs(),
                    log_path.display()
                ));
            }
            if injecting && last_injection.elapsed() >= REINJECT_INTERVAL {
                match writer.write_all(&wire) {
                    Ok(()) => last_injection = Instant::now(),
                    // A write failure means QEMU closed the socket (it is
                    // exiting); stop injecting and let the exit/timeout checks
                    // above decide the outcome.
                    Err(_error) => injecting = false,
                }
            }
            thread::sleep(Duration::from_millis(25));
        }
        // `writer` drops here, closing our write side of the NIC socket.
    };

    // Reliable shutdown: kill and reap QEMU on every path before joining the
    // reader threads (which unblock once the pipes and socket close).
    let terminate_result = terminate(&mut child, "nic test finished");
    let stdout_result = join_reader(stdout_reader, "stdout");
    let stderr_result = join_reader(stderr_reader, "stderr");
    let socket_result = match socket_reader {
        Some(handle) => join_reader(handle, "NIC socket"),
        None => Ok(()),
    };
    drain(&receiver, &mut output);

    // Always persist the captured serial output before propagating any error.
    write_capture(log_path, &output)?;

    outcome?;
    terminate_result?;
    stdout_result?;
    stderr_result?;
    socket_result?;
    Ok(())
}

/// Build the broadcast frame injected into the guest: a minimum-size Ethernet
/// frame carrying the RX marker under the local-experimental EtherType 0x88B5.
fn build_injection_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(MIN_ETHERNET_FRAME);
    frame.extend_from_slice(&[0xff; 6]); // dst: broadcast
    frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // src
    frame.extend_from_slice(&[0x88, 0xB5]); // ethertype: experimental 0x88B5
    frame.extend_from_slice(b"LIBREFIREWALL-NIC-RX");
    // Zero-pad to the 60-byte minimum L2 frame (FCS excluded on this backend).
    if frame.len() < MIN_ETHERNET_FRAME {
        frame.resize(MIN_ETHERNET_FRAME, 0);
    }
    frame
}

/// Encode a frame for QEMU's `net_socket` STREAM backend: a 4-byte big-endian
/// (network order) length header followed by the raw frame bytes.
fn encode_wire(frame: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(4 + frame.len());
    wire.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    wire.extend_from_slice(frame);
    wire
}

/// Move every currently buffered serial chunk into `output`.
fn drain(receiver: &mpsc::Receiver<Vec<u8>>, output: &mut Vec<u8>) {
    while let Ok(chunk) = receiver.try_recv() {
        output.extend_from_slice(&chunk);
    }
}

/// Read the guest's transmitted frames from the NIC socket and discard them, so
/// QEMU's TX path never blocks on a full host socket buffer.
fn spawn_socket_drain(mut stream: TcpStream) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(_count) => {} // discard guest TX
                Err(ref error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    })
}

/// Stream a piped child output into `sender` until EOF.
fn spawn_reader<R>(mut reader: R, sender: mpsc::Sender<Vec<u8>>) -> JoinHandle<io::Result<()>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                return Ok(());
            }
            if sender.send(buffer[..count].to_vec()).is_err() {
                return Ok(());
            }
        }
    })
}

/// Join a reader thread, flattening a panic and an I/O error into a message.
fn join_reader(handle: JoinHandle<io::Result<()>>, name: &str) -> Result<(), String> {
    handle
        .join()
        .map_err(|_| format!("QEMU {name} reader panicked"))?
        .map_err(|error| format!("read QEMU {name}: {error}"))
}

/// Kill and reap the QEMU child, tolerating a process that has already exited.
fn terminate(child: &mut Child, reason: &str) -> Result<(), String> {
    match child.kill() {
        Ok(()) => {}
        Err(_error) if child.try_wait().ok().flatten().is_some() => {}
        Err(error) => return Err(format!("kill QEMU after {reason}: {error}")),
    }
    child
        .wait()
        .map_err(|error| format!("reap QEMU after {reason}: {error}"))?;
    Ok(())
}

/// Write the captured serial output to `path`, creating parent directories.
fn write_capture(path: &Path, output: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(path, output).map_err(|error| format!("write {}: {error}", path.display()))
}

/// Count non-overlapping-position occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn require_file(path: &Path) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("required file is missing: {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_frame_and_wire_encoding_are_well_formed() {
        let frame = build_injection_frame();

        assert!(
            frame.len() >= 60,
            "frame must meet the 60-byte minimum Ethernet size, got {}",
            frame.len()
        );
        assert_eq!(
            &frame[0..6],
            [0xff_u8; 6].as_slice(),
            "destination MAC must be broadcast"
        );
        assert_eq!(
            &frame[12..14],
            [0x88_u8, 0xB5].as_slice(),
            "EtherType must be the experimental 0x88B5"
        );
        assert!(
            frame[14..].starts_with(b"LIBREFIREWALL-NIC-RX"),
            "payload must begin with the RX marker"
        );

        // Wire form is the big-endian u32 length prefix followed by the frame.
        let wire = encode_wire(&frame);
        let mut expected = (frame.len() as u32).to_be_bytes().to_vec();
        expected.extend_from_slice(&frame);
        assert_eq!(wire, expected);
        assert_eq!(&wire[0..4], (frame.len() as u32).to_be_bytes().as_slice());
        assert_eq!(&wire[4..], frame.as_slice());
    }
}
