//! Example showing how to integrate mzmq with a smoltcp TCP stack.
//!
//! Run with:
//! ```sh
//! cargo run --example smoltcp_pub --features "smoltcp,std"
//! ```
//!
//! This example uses a loopback device to demonstrate the integration pattern
//! (it won't handshake without a real peer). Replace with a real device
//! and remote ZMQ endpoint for actual use.
//!
//! Key pattern:
//! - [`smoltcp::iface::Interface::poll`] drives the TCP stack (drains/fills socket buffers)
//! - [`mzmq::io::smoltcp::TcpAdapter`] bridges the socket to `embedded_io` traits
//! - The mzmq sans-IO state machine (`Connection`) is driven with data from the adapter

#[cfg(all(feature = "smoltcp", feature = "std"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use embedded_io::{Read, Write};
    use mzmq::connection::{Connection, State};
    use mzmq::io::smoltcp::TcpAdapter;
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::socket::tcp::Socket;
    use smoltcp::time::Instant;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

    // 1. Create the network interface
    let mut device = Loopback::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24))
            .unwrap();
    });

    // 2. Set up TCP socket buffers
    let mut tcp_rx_storage = [0u8; 2048];
    let mut tcp_tx_storage = [0u8; 2048];
    let tcp_socket = Socket::new(
        smoltcp::storage::RingBuffer::new(&mut tcp_rx_storage[..]),
        smoltcp::storage::RingBuffer::new(&mut tcp_tx_storage[..]),
    );

    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(tcp_socket);

    // 3. Connect to the ZMQ endpoint (replace with real address)
    sockets.get_mut::<Socket>(handle).connect(
        iface.context(),
        IpEndpoint::new(IpAddress::v4(192, 168, 1, 100), 5556),
        49152,
    )?;

    // 4. Create the mzmq sans-IO connection
    let mut conn = Connection::<8, 32, 1024>::new();
    let mut greeting_done = false;
    let mut greeting_buf: Option<([u8; 64], usize)> = None;
    let mut rx_buf = [0u8; 512];
    let mut rx_len = 0;
    let mut established = false;

    // smoltcp's `SocketSet<'a>` uses invariant `&mut` which Rust's borrow
    // checker cannot handle across loop iterations. Use a raw pointer to
    // create fresh mutable references each iteration.
    // SAFETY: `sockets` is never accessed directly while a derived `&mut`
    // reference exists inside the unsafe block.
    let sockets_ptr = &raw mut sockets;

    // 5. Main loop — interleave smoltcp and mzmq polling
    loop {
        // Drive the TCP stack
        iface.poll(Instant::now(), &mut device, &mut sockets);

        // Process one round of ZMTP I/O through the socket
        let socket = unsafe { &mut *sockets_ptr }.get_mut::<Socket>(handle);
        let mut transport = TcpAdapter(socket);

        // Send greeting — encode once, retry write until TCP is writable
        if !greeting_done {
            if greeting_buf.is_none() {
                let mut buf = [0u8; 64];
                let n = conn
                    .write_greeting(&mut buf)
                    .map_err(|e| format!("greeting: {e:?}"))?;
                greeting_buf = Some((buf, n));
            }
            let (greeting, n) = greeting_buf.as_ref().unwrap();
            if transport.write_all(&greeting[..*n]).is_ok() {
                greeting_done = true;
            }
        }

        // Read incoming data
        match transport.read(&mut rx_buf[rx_len..]) {
            Ok(0) => {}
            Ok(n) => rx_len += n,
            Err(_) => {}
        }

        // Feed into the ZMTP state machine
        if rx_len > 0 {
            let prev_rx = rx_len;
            if let Ok(consumed) = conn.feed(&rx_buf[..rx_len])
                && consumed > 0
            {
                rx_buf.copy_within(consumed..rx_len, 0);
                rx_len -= consumed;
            }
            if rx_len == prev_rx && rx_len > 0 {
                rx_len = 0;
            }
        }

        // Handle handshake state transitions
        if let State::Ready = *conn.state() {
            let mut ready = [0u8; 32];
            if let Ok(n) = conn.write_ready(&mut ready) {
                let _ = transport.write_all(&ready[..n]);
            }
        }

        // Handle PONG
        let mut pong = [0u8; 23];
        if let Ok(Some(n)) = conn.write_pong(&mut pong) {
            let _ = transport.write_all(&pong[..n]);
        }

        // Publish when established
        if *conn.state() == State::Established {
            if !established {
                established = true;
                println!("Handshake complete — ready to publish");
            }
            if let Ok(Some((th, th_n, ph, ph_n))) = conn.publish_headers(b"hello", b"world") {
                let _ = transport.write_all(&th[..th_n]);
                let _ = transport.write_all(b"hello");
                let _ = transport.write_all(&ph[..ph_n]);
                let _ = transport.write_all(b"world");
            }
        }
        // transport dropped — socket borrow released
    }
}

#[cfg(not(all(feature = "smoltcp", feature = "std")))]
fn main() {
    eprintln!("This example requires --features \"smoltcp,std\"");
}
