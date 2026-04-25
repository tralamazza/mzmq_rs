fn main() {
    run()
}

#[cfg(all(feature = "async", feature = "std"))]
fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <host:port>", args[0]);
        std::process::exit(1);
    }
    let addr = args[1].clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");
    rt.block_on(pub_task(addr));
}

// Wraps tokio::net::TcpStream as an embedded_io_async transport with truly
// non-blocking I/O. On a real embedded target, replace this with a type that
// implements embedded_io_async::Read + Write for your hardware (e.g.
// embassy_net::tcp::TcpSocket).
#[cfg(all(feature = "async", feature = "std"))]
struct Transport(tokio::net::TcpStream);

#[cfg(all(feature = "async", feature = "std"))]
impl embedded_io_async::ErrorType for Transport {
    type Error = embedded_io_async::ErrorKind;
}

#[cfg(all(feature = "async", feature = "std"))]
impl embedded_io_async::Read for Transport {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        use tokio::io::AsyncReadExt;
        self.0
            .read(buf)
            .await
            .map_err(|_| embedded_io_async::ErrorKind::Other)
    }
}

#[cfg(all(feature = "async", feature = "std"))]
impl embedded_io_async::Write for Transport {
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

#[cfg(all(feature = "async", feature = "std"))]
async fn handshake(
    driver: &mut mzmq::io::r#async::Driver<
        8,
        32,
        1024,
        impl embedded_io_async::Read + embedded_io_async::Write,
    >,
) {
    use std::time::{Duration, Instant};

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

    if !established {
        eprintln!("Handshake timed out");
        std::process::exit(1);
    }
}

#[cfg(all(feature = "async", feature = "std"))]
async fn pub_task(addr: String) {
    use mzmq::io::r#async::Driver;
    use std::time::Duration;
    use tokio::net::TcpStream;

    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Connection failed: {e}");
            std::process::exit(1);
        }
    };

    let mut driver = match Driver::<8, 32, 1024, _>::new(Transport(stream)).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Driver creation failed: {e:?}");
            std::process::exit(1);
        }
    };

    println!("Connecting to {addr}...");
    handshake(&mut driver).await;

    println!("Handshake complete, publishing...");

    let topic = b"hello";
    let payload = b"world";

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut published = false;

    while std::time::Instant::now() < deadline {
        let _ = driver.poll().await;
        match driver.publish(topic, payload).await {
            Ok(n) if n > 0 => {
                println!(
                    "Published {n} bytes: {} -> {}",
                    String::from_utf8_lossy(topic),
                    String::from_utf8_lossy(payload)
                );
                published = true;
                break;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Publish failed: {e:?}");
                std::process::exit(1);
            }
        }
    }

    if !published {
        println!("No subscriber matched (empty subscription table)");
    }
}

#[cfg(not(all(feature = "async", feature = "std")))]
fn run() {
    eprintln!("mzmq compiled without async+std features");
    eprintln!("Enable async and std features to run this example");
    std::process::exit(1);
}
