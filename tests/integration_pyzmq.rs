//! Integration tests against real pyzmq.
//!
//! These tests spawn a Python SUB socket as a child process, connect to it
//! with our Rust PUB implementation, and verify that messages are received.

#[cfg(feature = "python-tests")]
mod python_tests {
    use std::io::{self, BufRead, BufReader};
    use std::net::TcpStream;
    use std::process::{Child, ChildStdout, Command, Stdio};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
    use std::thread;
    use std::time::{Duration, Instant};

    #[cfg(feature = "sync")]
    use embedded_io_adapters::std::FromStd;
    #[cfg(feature = "sync")]
    use mzmq::io::sync::Driver;

    /// Guard that kills a child process on drop.
    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    impl ChildGuard {
        fn new(child: Child) -> Self {
            Self(child)
        }
    }

    /// Drain a child's stdout into an mpsc channel, one line per message.
    ///
    /// The thread is detached. It exits when the pipe closes (EOF after the
    /// `ChildGuard` kills the child) or when the receiver is dropped.
    fn spawn_line_reader(stdout: ChildStdout) -> Receiver<io::Result<String>> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut buf = String::new();
                match reader.read_line(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {
                        if tx.send(Ok(buf)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        break;
                    }
                }
            }
        });
        rx
    }

    /// Spawn a Python SUB listener on an ephemeral port.
    ///
    /// Returns (guard, port, line receiver). The receiver yields each stdout
    /// line as `Ok(String)` and surfaces pipe errors as `Err`.
    fn spawn_sub_listener(topic_prefix: &str) -> (ChildGuard, u16, Receiver<io::Result<String>>) {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let child = Command::new("uv")
            .arg("run")
            .arg("tests/fixtures/sub_listener.py")
            .arg(port.to_string())
            .arg(topic_prefix)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn Python sub listener");

        let mut guard = ChildGuard::new(child);
        let stdout = guard.0.stdout.take().unwrap();
        let rx = spawn_line_reader(stdout);

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            match rx.recv_timeout(remaining) {
                Ok(Ok(line)) if line.contains("READY") => return (guard, port, rx),
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => panic!("Python SUB stdout read error before READY: {e}"),
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("Python SUB stdout closed before READY")
                }
                Err(RecvTimeoutError::Timeout) => {
                    panic!("Python SUB listener did not become ready within 5s")
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "sync")]
    fn pyzmq_sub_receives_single_publish() {
        let (_guard, port, rx) = spawn_sub_listener("");

        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .expect("failed to connect to Python SUB");
        // embedded-io has blocking-only semantics (no WouldBlock). Give the
        // socket a short read timeout so poll() returns periodically and the
        // test can drive the handshake without hanging on a slow peer.
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set_read_timeout");

        let transport = FromStd::new(stream);
        let mut driver = Driver::<8, 32, 512, _>::new(transport).expect("failed to create driver");

        let handshake_deadline = Instant::now() + Duration::from_secs(5);
        let mut established = false;
        while Instant::now() < handshake_deadline {
            match driver.poll() {
                Ok(true) => {
                    established = true;
                    break;
                }
                Ok(false) => {}
                // Any error here is likely a read timeout — retry until deadline.
                Err(_) => {}
            }
        }
        assert!(established, "Handshake should complete within 5s");

        let topic = b"test";
        let payload = b"hello world";

        // Slow-joiner pattern: Python's SUBSCRIBE may arrive in a separate TCP
        // segment after its READY. Retry publish until subscription is visible.
        let publish_deadline = Instant::now() + Duration::from_secs(2);
        let mut wrote = 0;
        while Instant::now() < publish_deadline {
            // Drain any incoming SUBSCRIBE. Error is a timeout; keep going.
            let _ = driver.poll();
            match driver
                .publish(topic, payload)
                .expect("publish should not error")
            {
                0 => std::thread::sleep(Duration::from_millis(50)),
                n => {
                    wrote = n;
                    break;
                }
            }
        }
        assert!(wrote > 0, "Should eventually publish once peer subscribes");

        let line = match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => panic!("stdout read error: {e}"),
            Err(RecvTimeoutError::Timeout) => {
                panic!("No message received from Python SUB within timeout")
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("Python SUB stdout closed before producing a message")
            }
        };

        println!("Received: {}", line.trim());

        let parts: Vec<&str> = line.trim().split(':').collect();
        assert_eq!(parts.len(), 2, "Expected format: hex(topic):hex(payload)");

        let received_topic = hex::decode(parts[0]).expect("topic should be valid hex");
        let received_payload = hex::decode(parts[1]).expect("payload should be valid hex");

        assert_eq!(received_topic, topic, "Topic should match");
        assert_eq!(received_payload, payload, "Payload should match");
    }

    #[cfg(all(feature = "async", feature = "std"))]
    mod tokio_helpers {
        use tokio::net::TcpStream;

        pub(super) struct AsyncTransport(pub TcpStream);

        impl embedded_io_async::ErrorType for AsyncTransport {
            type Error = embedded_io_async::ErrorKind;
        }

        impl embedded_io_async::Read for AsyncTransport {
            async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
                use tokio::io::AsyncReadExt;
                self.0
                    .read(buf)
                    .await
                    .map_err(|_| embedded_io_async::ErrorKind::Other)
            }
        }

        impl embedded_io_async::Write for AsyncTransport {
            async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
                use tokio::io::AsyncWriteExt;
                self.0
                    .write(buf)
                    .await
                    .map_err(|_| embedded_io_async::ErrorKind::Other)
            }

            async fn flush(&mut self) -> Result<(), Self::Error> {
                use tokio::io::AsyncWriteExt;
                self.0
                    .flush()
                    .await
                    .map_err(|_| embedded_io_async::ErrorKind::Other)
            }
        }
    }

    #[tokio::test]
    #[cfg(all(feature = "async", feature = "std"))]
    async fn async_pyzmq_sub_receives_single_publish() {
        use mzmq::io::r#async::Driver;
        use tokio_helpers::AsyncTransport;

        let (_guard, port, rx) = spawn_sub_listener("");

        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .expect("failed to connect to Python SUB");

        let transport = AsyncTransport(stream);

        let mut driver = match Driver::<8, 32, 512, _>::new(transport).await {
            Ok(d) => d,
            Err(e) => panic!("Driver creation failed: {e:?}"),
        };

        // Handshake with deadline
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut established = false;
        while Instant::now() < deadline {
            match driver.poll().await {
                Ok(true) => {
                    established = true;
                    break;
                }
                Ok(false) => {}
                Err(_) => {}
            }
        }
        assert!(established, "Handshake should complete within 5s");

        let topic = b"test";
        let payload = b"hello world";

        // Publish with retry
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut wrote = 0;
        while Instant::now() < deadline {
            let _ = driver.poll().await;
            match driver.publish(topic, payload).await {
                Ok(0) => tokio::time::sleep(Duration::from_millis(50)).await,
                Ok(n) => {
                    wrote = n;
                    break;
                }
                Err(e) => panic!("publish error: {e:?}"),
            }
        }
        assert!(wrote > 0, "Should eventually publish once peer subscribes");

        let recv_result =
            tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(2)))
                .await
                .expect("reader task panicked");

        let line = match recv_result {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => panic!("stdout read error: {e}"),
            Err(RecvTimeoutError::Timeout) => {
                panic!("No message received from Python SUB within timeout")
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("Python SUB stdout closed before producing a message")
            }
        };

        println!("Received: {}", line.trim());

        let parts: Vec<&str> = line.trim().split(':').collect();
        assert_eq!(parts.len(), 2, "Expected format: hex(topic):hex(payload)");

        let received_topic = hex::decode(parts[0]).expect("topic should be valid hex");
        let received_payload = hex::decode(parts[1]).expect("payload should be valid hex");

        assert_eq!(received_topic, topic.as_ref(), "Topic should match");
        assert_eq!(received_payload, payload.as_ref(), "Payload should match");
    }
}

#[test]
#[cfg(feature = "sync")]
fn sync_driver_completes_handshake_and_publishes() {
    use embedded_io::{ErrorKind, ErrorType, Read, Write};

    struct MockSubTransport {
        to_pub: Vec<u8>,
        to_pub_pos: usize,
        from_pub: Vec<u8>,
    }

    impl MockSubTransport {
        fn new() -> Self {
            let mut sub_greeting = [0u8; 64];
            sub_greeting[0] = 0xFF;
            sub_greeting[9] = 0x7F;
            sub_greeting[10] = 0x03;
            sub_greeting[11] = 0x01;
            sub_greeting[12] = b'N';
            sub_greeting[13] = b'U';
            sub_greeting[14] = b'L';
            sub_greeting[15] = b'L';

            let sub_ready = [
                0x04, 0x19, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
                0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x03, 0x53, 0x55, 0x42,
            ];

            let mut to_pub = Vec::new();
            to_pub.extend_from_slice(&sub_greeting);
            to_pub.extend_from_slice(&sub_ready);

            Self {
                to_pub,
                to_pub_pos: 0,
                from_pub: Vec::new(),
            }
        }
    }

    impl ErrorType for MockSubTransport {
        type Error = ErrorKind;
    }

    impl Read for MockSubTransport {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if self.to_pub_pos >= self.to_pub.len() {
                return Ok(0);
            }
            let to_copy = std::cmp::min(buf.len(), self.to_pub.len() - self.to_pub_pos);
            buf[..to_copy]
                .copy_from_slice(&self.to_pub[self.to_pub_pos..self.to_pub_pos + to_copy]);
            self.to_pub_pos += to_copy;
            Ok(to_copy)
        }
    }

    impl Write for MockSubTransport {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.from_pub.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    let transport = MockSubTransport::new();
    let mut driver = mzmq::io::sync::Driver::<8, 32, 512, _>::new(transport).unwrap();

    let mut established = false;
    for _ in 0..10 {
        match driver.poll() {
            Ok(true) => {
                established = true;
                break;
            }
            Ok(false) => {}
            Err(e) => {
                panic!("Poll failed during handshake: {:?}", e);
            }
        }
    }

    assert!(
        established,
        "Handshake should complete and connection should be established"
    );

    let publish_result = driver.publish(b"test", b"hello");
    assert_eq!(
        publish_result.unwrap(),
        0,
        "Should return 0 bytes written when no subscription matches"
    );
}
