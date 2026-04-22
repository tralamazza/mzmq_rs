fn main() {
    run()
}

#[cfg(all(feature = "sync", feature = "std"))]
fn run() {
    use embedded_io_adapters::std::FromStd;
    use mzmq::io::sync::Driver;
    use std::net::TcpStream;
    use std::time::Duration;

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <host:port>", args[0]);
        std::process::exit(1);
    }

    let addr = &args[1];
    println!("Connecting to {}...", addr);

    let stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Connection failed: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = stream.set_read_timeout(Some(Duration::from_millis(200))) {
        eprintln!("set_read_timeout failed: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = stream.set_nonblocking(true) {
        eprintln!("set_nonblocking failed: {}", e);
        std::process::exit(1);
    }

    let transport = FromStd::new(stream);
    let mut driver = match Driver::<8, 32, 1024, _>::new(transport) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Driver creation failed: {:?}", e);
            std::process::exit(1);
        }
    };

    handshake(&mut driver);
}

#[cfg(all(feature = "sync", feature = "std"))]
fn handshake(
    driver: &mut mzmq::io::sync::Driver<
        8,
        32,
        1024,
        embedded_io_adapters::std::FromStd<std::net::TcpStream>,
    >,
) {
    use std::time::Duration;

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut established = false;

    while std::time::Instant::now() < deadline {
        match driver.poll() {
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

    println!("Handshake complete, publishing...");

    let topic = b"hello";
    let payload = b"world";

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut published = false;

    while std::time::Instant::now() < deadline {
        let _ = driver.poll();
        match driver.publish(topic, payload) {
            Ok(n) => {
                if n > 0 {
                    println!(
                        "Published {} bytes: {} -> {}",
                        n,
                        String::from_utf8_lossy(topic),
                        String::from_utf8_lossy(payload)
                    );
                    published = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("Publish failed: {:?}", e);
                std::process::exit(1);
            }
        }
    }

    if !published {
        println!("No subscriber matched (empty subscription table)");
    }
}

#[cfg(not(all(feature = "sync", feature = "std")))]
fn run() {
    eprintln!("mzmq compiled without sync+std features");
    eprintln!("Enable sync and std features to run this example");
    std::process::exit(1);
}
