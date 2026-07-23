//! QEMU two-port virtio-net forwarding harness.
//!
//! Boots the seL4/Microkit x86_64 forwarding image in QEMU with two
//! `virtio-net-pci` NICs whose backends are host-controlled TCP sockets,
//! injects one Ethernet frame into each port, and asserts that each frame
//! egresses — byte-identical — on the *other* port before a timeout. The
//! observable contract is the frames themselves on the sockets, not serial
//! text; the guest serial output is captured to a log for diagnostics only.
//!
//! This module is intentionally self-contained: it duplicates the small
//! process and capture helpers from `main.rs` rather than depending on its
//! private items, so it can be dropped into the `xtask` binary with a single
//! `mod forward_harness;`.

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

/// Total wall-clock budget from QEMU launch to both frames observed. TCG (no
/// KVM) boot of seL4 plus two polling virtio drivers is slow, hence the
/// generous ceiling.
const FORWARD_TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for QEMU to dial back into both listeners before giving up.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);

/// Cadence of re-injection. virtio-net silently drops received frames while
/// the guest driver has not yet posted RX buffers, so a single early frame can
/// be lost; we resend until the guest forwards or the test times out.
const REINJECT_INTERVAL: Duration = Duration::from_millis(500);

/// Minimum Ethernet frame size on the wire without FCS.
const MIN_ETHERNET_FRAME: usize = 60;

/// Upper bound on a frame length announced by QEMU's socket framing; anything
/// larger means a corrupt stream, not a jumbo frame.
const MAX_WIRE_FRAME: usize = 65535;

/// Boot the image in QEMU with two socket-backed NICs, inject a distinct
/// broadcast frame into each port, and assert each frame comes back out of the
/// opposite port unchanged — the two-port zero-copy forwarding contract, in
/// both directions at once.
///
/// `kernel` is the 32-bit seL4 kernel ELF (`sel4_32.elf`) loaded as the
/// Multiboot2 payload; `system` is the Microkit loader image (`loader.img`)
/// loaded as the initrd. The captured serial output is always written to
/// `log_path` (whose parent directories are created), whether the test passes
/// or fails, and QEMU is always killed and reaped on every exit path.
pub fn run_forward_test(
    root: &Path,
    kernel: &Path,
    system: &Path,
    log_path: &Path,
) -> Result<(), String> {
    require_file(kernel)?;
    require_file(system)?;

    // One ephemeral loopback listener per port; QEMU's `connect=` backends
    // dial in to us, each netdev to its own listener, so the port identity of
    // each accepted stream is unambiguous.
    let listeners = [bind_listener()?, bind_listener()?];

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
        .arg("-no-reboot")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (port, (listener, pci_device)) in listeners.iter().zip(["02.0", "03.0"]).enumerate() {
        let tcp = listener
            .local_addr()
            .map_err(|error| format!("read listener port: {error}"))?
            .port();
        command
            .arg("-netdev")
            .arg(format!("socket,id=n{port},connect=127.0.0.1:{tcp}"))
            .arg("-device")
            .arg(format!(
                "virtio-net-pci,netdev=n{port},disable-legacy=on,disable-modern=off,\
                 mac=52:54:00:12:34:5{port},bus=pcie.0,addr={pci_device}",
            ));
    }

    let mut child = command
        .spawn()
        .map_err(|error| format!("start QEMU: {error}"))?;

    // Serial output arrives on both pipes; reader threads funnel it into a
    // single channel the timeout loop drains.
    let (serial_sender, serial_receiver) = mpsc::channel();
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
    let stdout_reader = spawn_reader(stdout, serial_sender.clone());
    let stderr_reader = spawn_reader(stderr, serial_sender);

    let start = Instant::now();
    let mut output: Vec<u8> = Vec::new();
    // Kept alive across finalisation so they can be joined after QEMU dies.
    let mut frame_readers: Vec<JoinHandle<io::Result<()>>> = Vec::new();

    let outcome: Result<(), String> = 'run: {
        // Phase 1: accept both of QEMU's socket dial-ins.
        let mut streams: [Option<TcpStream>; 2] = [None, None];
        while streams.iter().any(Option::is_none) {
            drain(&serial_receiver, &mut output);
            for (port, listener) in listeners.iter().enumerate() {
                if streams[port].is_some() {
                    continue;
                }
                match listener.accept() {
                    Ok((stream, _peer)) => streams[port] = Some(stream),
                    Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => break 'run Err(format!("accept QEMU NIC socket: {error}")),
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    break 'run Err(format!(
                        "QEMU exited before connecting its NIC sockets ({status})"
                    ));
                }
                Ok(None) => {}
                Err(error) => break 'run Err(format!("poll QEMU: {error}")),
            }
            if start.elapsed() >= ACCEPT_TIMEOUT {
                break 'run Err(format!(
                    "QEMU did not connect both NIC sockets within {}s",
                    ACCEPT_TIMEOUT.as_secs()
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
        let streams = streams.map(|stream| stream.expect("both streams accepted"));

        // Each stream carries QEMU's `net_socket` STREAM framing in both
        // directions: a 4-byte big-endian length header followed by the raw L2
        // bytes (no FCS). A decoder thread per port parses the guest's egress
        // frames into one channel; draining continuously also keeps QEMU's TX
        // ring from blocking on a full host socket buffer.
        let (frame_sender, frame_receiver) = mpsc::channel();
        let mut writers = Vec::new();
        for (port, stream) in streams.into_iter().enumerate() {
            if let Err(error) = stream.set_nonblocking(false) {
                break 'run Err(format!("set NIC socket blocking: {error}"));
            }
            let read_half = match stream.try_clone() {
                Ok(handle) => handle,
                Err(error) => break 'run Err(format!("clone NIC socket: {error}")),
            };
            frame_readers.push(spawn_frame_decoder(port, read_half, frame_sender.clone()));
            writers.push(stream);
        }
        drop(frame_sender);

        // Distinct frames per direction; each must egress on the other port.
        let frames = [
            build_injection_frame(b"LIBREFIREWALL-FWD-P0-TO-P1"),
            build_injection_frame(b"LIBREFIREWALL-FWD-P1-TO-P0"),
        ];
        let wires = [encode_wire(&frames[0]), encode_wire(&frames[1])];

        // Inject immediately; the drivers may not be ready yet, which is
        // exactly why we also re-inject on a fixed cadence below.
        let mut injecting = true;
        let mut last_injection = Instant::now();
        for (writer, wire) in writers.iter_mut().zip(&wires) {
            if let Err(error) = writer.write_all(wire) {
                break 'run Err(format!("inject first frames: {error}"));
            }
        }

        // Phase 2: watch for both forwarded frames, re-injecting periodically.
        let mut forwarded = [false, false];
        loop {
            drain(&serial_receiver, &mut output);
            while let Ok((egress_port, frame)) = frame_receiver.try_recv() {
                // The frame injected into a port must egress on the other
                // port, byte-identical — the zero-copy path may not alter it.
                let ingress_port = 1 - egress_port;
                if frame == frames[ingress_port] {
                    forwarded[ingress_port] = true;
                }
            }
            if forwarded.iter().all(|seen| *seen) {
                break 'run Ok(());
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    break 'run Err(format!(
                        "QEMU exited before both frames were forwarded ({status}); see {}",
                        log_path.display()
                    ));
                }
                Ok(None) => {}
                Err(error) => break 'run Err(format!("poll QEMU: {error}")),
            }
            if start.elapsed() >= FORWARD_TEST_TIMEOUT {
                break 'run Err(format!(
                    "timed out after {}s waiting for forwarded frames \
                     (port0->port1 seen: {}, port1->port0 seen: {}); see {}",
                    FORWARD_TEST_TIMEOUT.as_secs(),
                    forwarded[0],
                    forwarded[1],
                    log_path.display()
                ));
            }
            if injecting && last_injection.elapsed() >= REINJECT_INTERVAL {
                last_injection = Instant::now();
                for (port, writer) in writers.iter_mut().enumerate() {
                    if forwarded[port] {
                        continue;
                    }
                    // A write failure means QEMU closed the socket (it is
                    // exiting); stop injecting and let the exit/timeout checks
                    // above decide the outcome.
                    if writer.write_all(&wires[port]).is_err() {
                        injecting = false;
                    }
                }
            }
            thread::sleep(Duration::from_millis(25));
        }
        // `writers` drop here, closing our write sides of the NIC sockets.
    };

    // Reliable shutdown: kill and reap QEMU on every path before joining the
    // reader threads (which unblock once the pipes and sockets close).
    let terminate_result = terminate(&mut child, "forward test finished");
    let stdout_result = join_reader(stdout_reader, "stdout");
    let stderr_result = join_reader(stderr_reader, "stderr");
    let mut frame_reader_result = Ok(());
    for handle in frame_readers {
        frame_reader_result = frame_reader_result.and(join_reader(handle, "NIC socket"));
    }
    drain(&serial_receiver, &mut output);

    // Always persist the captured serial output before propagating any error.
    write_capture(log_path, &output)?;

    outcome?;
    terminate_result?;
    stdout_result?;
    stderr_result?;
    frame_reader_result?;
    Ok(())
}

fn bind_listener() -> Result<TcpListener, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("bind harness listener: {error}"))?;
    // Non-blocking accept lets the timeout loop keep draining serial output
    // while it waits for QEMU to connect.
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set listener non-blocking: {error}"))?;
    Ok(listener)
}

/// Build a broadcast frame to inject: a minimum-size Ethernet frame carrying
/// `marker` under the local-experimental EtherType 0x88B5.
fn build_injection_frame(marker: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(MIN_ETHERNET_FRAME);
    frame.extend_from_slice(&[0xff; 6]); // dst: broadcast
    frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // src
    frame.extend_from_slice(&[0x88, 0xB5]); // ethertype: experimental 0x88B5
    frame.extend_from_slice(marker);
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

/// Decode the guest's egress frames from one NIC socket (QEMU's length-framed
/// STREAM encoding) and send each as `(port, frame)` until the stream closes.
fn spawn_frame_decoder(
    port: usize,
    mut stream: TcpStream,
    sender: mpsc::Sender<(usize, Vec<u8>)>,
) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        loop {
            let mut header = [0u8; 4];
            match stream.read_exact(&mut header) {
                Ok(()) => {}
                // A closed or reset socket is QEMU exiting: a normal end.
                Err(ref error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            let length = u32::from_be_bytes(header) as usize;
            if length > MAX_WIRE_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("NIC socket announced an implausible frame length {length}"),
                ));
            }
            let mut frame = vec![0u8; length];
            match stream.read_exact(&mut frame) {
                Ok(()) => {}
                Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            }
            if sender.send((port, frame)).is_err() {
                return Ok(());
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
    fn injection_frames_and_wire_encoding_are_well_formed() {
        let frame = build_injection_frame(b"LIBREFIREWALL-FWD-P0-TO-P1");

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
            frame[14..].starts_with(b"LIBREFIREWALL-FWD-P0-TO-P1"),
            "payload must begin with the direction marker"
        );

        // The two directions must be distinguishable by exact frame bytes.
        let reverse = build_injection_frame(b"LIBREFIREWALL-FWD-P1-TO-P0");
        assert_ne!(frame, reverse);

        // Wire form is the big-endian u32 length prefix followed by the frame.
        let wire = encode_wire(&frame);
        assert_eq!(&wire[0..4], (frame.len() as u32).to_be_bytes().as_slice());
        assert_eq!(&wire[4..], frame.as_slice());
    }

    #[test]
    fn frame_decoder_reassembles_length_framed_frames() {
        // A local socket pair carrying two frames in QEMU's framing, the
        // second arriving byte-dribbled, must decode into exactly those
        // frames tagged with the decoder's port.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut writer = TcpStream::connect(address).unwrap();
        let (stream, _peer) = listener.accept().unwrap();

        let (sender, receiver) = mpsc::channel();
        let decoder = spawn_frame_decoder(1, stream, sender);

        let first = build_injection_frame(b"FIRST");
        let second = build_injection_frame(b"SECOND");
        writer.write_all(&encode_wire(&first)).unwrap();
        for byte in encode_wire(&second) {
            writer.write_all(&[byte]).unwrap();
        }
        drop(writer);

        assert_eq!(receiver.recv().unwrap(), (1, first));
        assert_eq!(receiver.recv().unwrap(), (1, second));
        assert!(receiver.recv().is_err(), "decoder must close after EOF");
        decoder.join().unwrap().unwrap();
    }
}
