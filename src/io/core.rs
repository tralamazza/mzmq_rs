use crate::auth::AuthCheck;
use crate::connection::{self, Connection};
use crate::radio_connection::{self, RadioConnection};

// ---------------------------------------------------------------------------
// PUB core
// ---------------------------------------------------------------------------

pub(super) enum DriverPhase {
    AwaitingPeerGreeting,
    SendingGreetingRest,
    SendingReady,
    AwaitingPeerReady,
    #[cfg(feature = "plain")]
    AwaitingPlainHello,
    #[cfg(feature = "plain")]
    SendingPlainWelcome,
    #[cfg(feature = "plain")]
    SendingPlainReady,
    #[cfg(feature = "plain")]
    AwaitingPlainReady,
    Established,
    Failed,
}

#[derive(Debug)]
pub(super) enum Action<'a> {
    Read,
    Write(&'a [u8]),
    Established,
    Parked,
}

pub(super) struct DriverCore<
    const SUB_CAP: usize,
    const PREFIX_CAP: usize,
    const FRAME_CAP: usize,
    A: AuthCheck = (),
> {
    conn: Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP, A>,
    rx_buf: [u8; 512],
    rx_len: usize,
    tx_buf: [u8; 64],
    tx_len: usize,
    phase: DriverPhase,
    error: Option<connection::ConnError>,
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize, A: AuthCheck>
    DriverCore<SUB_CAP, PREFIX_CAP, FRAME_CAP, A>
{
    pub(super) fn new_null(conn: Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP, A>) -> Self {
        Self {
            conn,
            rx_buf: [0u8; 512],
            rx_len: 0,
            tx_buf: [0u8; 64],
            tx_len: 0,
            phase: DriverPhase::AwaitingPeerGreeting,
            error: None,
        }
    }

    /// New core for a PLAIN-mechanism connection (server role).
    ///
    /// Starts in [`DriverPhase::AwaitingPeerGreeting`] like NULL, but
    /// [`feed_until_transition`] detects the `PlainHello` state transition
    /// internally and switches to [`DriverPhase::AwaitingPlainHello`].
    #[cfg(feature = "plain")]
    pub(super) fn new_plain(conn: Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP, A>) -> Self {
        Self {
            conn,
            rx_buf: [0u8; 512],
            rx_len: 0,
            tx_buf: [0u8; 64],
            tx_len: 0,
            phase: DriverPhase::AwaitingPeerGreeting,
            error: None,
        }
    }

    pub(super) fn rx_slot(&mut self) -> &mut [u8] {
        &mut self.rx_buf[self.rx_len..]
    }

    pub(super) fn advance_rx(&mut self, n: usize) {
        self.rx_len += n;
    }

    pub(super) fn is_established(&self) -> bool {
        *self.conn.state() == connection::State::Established
    }

    #[cfg(test)]
    pub(super) fn conn(&self) -> &Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP, A> {
        &self.conn
    }

    pub(super) fn publish_headers(
        &mut self,
        topic: &[u8],
        payload: &[u8],
    ) -> Result<Option<connection::PublishHeaders>, connection::ConnError> {
        self.conn.publish_headers(topic, payload)
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn step(&mut self) -> Result<Action<'_>, connection::ConnError> {
        loop {
            if self.tx_len > 0 {
                let len = self.tx_len;
                self.tx_len = 0;
                return Ok(Action::Write(&self.tx_buf[..len]));
            }

            // "Sending" phases: the write was already queued in tx_buf by
            // feed_until_transition; after the caller writes it, reset to the
            // corresponding "Awaiting" phase so the next step continues
            // processing buffered rx data.
            match self.phase {
                DriverPhase::SendingGreetingRest => {
                    self.phase = DriverPhase::AwaitingPeerGreeting;
                    continue;
                }
                DriverPhase::SendingReady => {
                    self.phase = DriverPhase::AwaitingPeerReady;
                    continue;
                }
                #[cfg(feature = "plain")]
                DriverPhase::SendingPlainWelcome => {
                    let n = self.conn.write_ready(&mut self.tx_buf)?;
                    self.tx_len = n;
                    self.phase = DriverPhase::SendingPlainReady;
                    continue;
                }
                #[cfg(feature = "plain")]
                DriverPhase::SendingPlainReady => {
                    self.phase = DriverPhase::AwaitingPlainReady;
                    continue;
                }
                DriverPhase::Failed => {
                    return Err(self
                        .error
                        .take()
                        .unwrap_or(connection::ConnError::WrongState));
                }
                _ => {}
            }

            match self.phase {
                DriverPhase::AwaitingPeerGreeting => {
                    if *self.conn.state() == connection::State::Ready {
                        let n = self.conn.write_ready(&mut self.tx_buf)?;
                        self.tx_len = n;
                        self.phase = DriverPhase::SendingReady;
                        continue;
                    }
                    #[cfg(feature = "plain")]
                    if *self.conn.state() == connection::State::PlainHello {
                        self.phase = DriverPhase::AwaitingPlainHello;
                    }
                    if self.rx_len == 0 {
                        return Ok(Action::Read);
                    }
                    let consumed = self.feed_until_transition()?;
                    self.shift_rx(consumed);
                    if self.tx_len > 0 {
                        continue;
                    }
                    if self.rx_len > 0 {
                        return Ok(Action::Parked);
                    }
                    return Ok(Action::Read);
                }
                DriverPhase::AwaitingPeerReady => {
                    if *self.conn.state() == connection::State::Established {
                        self.phase = DriverPhase::Established;
                        return Ok(Action::Established);
                    }
                    if self.rx_len == 0 {
                        return Ok(Action::Read);
                    }
                    let consumed = self.feed_until_transition()?;
                    self.shift_rx(consumed);
                    if self.tx_len > 0 {
                        continue;
                    }
                    if *self.conn.state() == connection::State::Established {
                        self.phase = DriverPhase::Established;
                        return Ok(Action::Established);
                    }
                    if self.rx_len > 0 {
                        return Ok(Action::Parked);
                    }
                    return Ok(Action::Read);
                }
                #[cfg(feature = "plain")]
                DriverPhase::AwaitingPlainHello => {
                    if self.rx_len == 0 {
                        return Ok(Action::Read);
                    }
                    let consumed = self.feed_until_transition()?;
                    self.shift_rx(consumed);
                    if self.tx_len > 0 {
                        continue;
                    }
                    if self.rx_len > 0 {
                        return Ok(Action::Parked);
                    }
                    return Ok(Action::Read);
                }
                #[cfg(feature = "plain")]
                DriverPhase::AwaitingPlainReady => {
                    if *self.conn.state() == connection::State::Established {
                        self.phase = DriverPhase::Established;
                        return Ok(Action::Established);
                    }
                    if self.rx_len == 0 {
                        return Ok(Action::Read);
                    }
                    let consumed = self.feed_until_transition()?;
                    self.shift_rx(consumed);
                    if self.tx_len > 0 {
                        continue;
                    }
                    if *self.conn.state() == connection::State::Established {
                        self.phase = DriverPhase::Established;
                        return Ok(Action::Established);
                    }
                    if self.rx_len > 0 {
                        return Ok(Action::Parked);
                    }
                    return Ok(Action::Read);
                }
                DriverPhase::Established => {
                    if self.rx_len == 0 {
                        return Ok(Action::Read);
                    }
                    let consumed = self.feed_until_transition()?;
                    self.shift_rx(consumed);
                    if self.tx_len > 0 {
                        continue;
                    }
                    if self.rx_len > 0 {
                        return Ok(Action::Parked);
                    }
                    return Ok(Action::Read);
                }
                DriverPhase::Failed
                | DriverPhase::SendingGreetingRest
                | DriverPhase::SendingReady => unreachable!(),
                #[cfg(feature = "plain")]
                DriverPhase::SendingPlainWelcome | DriverPhase::SendingPlainReady => unreachable!(),
            }
        }
    }

    fn feed_until_transition(&mut self) -> Result<usize, connection::ConnError> {
        let mut total_consumed = 0;
        while total_consumed < self.rx_len {
            #[cfg(feature = "plain")]
            let prev_state = *self.conn.state();
            match self.conn.feed(&self.rx_buf[total_consumed..self.rx_len]) {
                Ok(consumed) => {
                    if consumed == 0 {
                        break;
                    }
                    total_consumed += consumed;

                    if self.conn.greeting_rest_pending() {
                        let n = self.conn.write_greeting_rest(&mut self.tx_buf)?;
                        self.tx_len = n;
                        self.phase = DriverPhase::SendingGreetingRest;
                        break;
                    }

                    #[cfg(feature = "plain")]
                    if *self.conn.state() == connection::State::PlainHello
                        && prev_state != connection::State::PlainHello
                        && prev_state != connection::State::PlainReady
                    {
                        self.phase = DriverPhase::AwaitingPlainHello;
                    }

                    #[cfg(feature = "plain")]
                    if *self.conn.state() == connection::State::PlainReady
                        && prev_state != connection::State::PlainReady
                    {
                        let n = self.conn.write_welcome(&mut self.tx_buf)?;
                        self.tx_len = n;
                        self.phase = DriverPhase::SendingPlainWelcome;
                        break;
                    }

                    let mut pong_buf = [0u8; 23];
                    if let Some(n) = self.conn.write_pong(&mut pong_buf)? {
                        self.tx_buf[..n].copy_from_slice(&pong_buf[..n]);
                        self.tx_len = n;
                        break;
                    }

                    if *self.conn.state() == connection::State::Failed {
                        self.phase = DriverPhase::Failed;
                        break;
                    }
                }
                Err(e) => {
                    if *self.conn.state() == connection::State::Failed {
                        if let Ok(n) = self.conn.write_error(&mut self.tx_buf) {
                            self.tx_len = n;
                        }
                        self.phase = DriverPhase::Failed;
                        self.error = Some(e);
                        break;
                    }
                    return Err(e);
                }
            }
        }
        Ok(total_consumed)
    }

    fn shift_rx(&mut self, consumed: usize) {
        if consumed > 0 {
            self.rx_buf.copy_within(consumed..self.rx_len, 0);
            self.rx_len -= consumed;
        }
    }
}

// ---------------------------------------------------------------------------
// RADIO core
// ---------------------------------------------------------------------------

pub(super) enum RadioDriverPhase {
    AwaitingPeerGreeting,
    SendingGreetingRest,
    SendingReady,
    AwaitingPeerReady,
    Established,
    Failed,
}

pub(super) struct RadioDriverCore<
    const GROUP_CAP: usize,
    const GROUP_LEN_CAP: usize,
    const FRAME_CAP: usize,
> {
    conn: RadioConnection<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP>,
    rx_buf: [u8; 512],
    rx_len: usize,
    tx_buf: [u8; 64],
    tx_len: usize,
    phase: RadioDriverPhase,
    error: Option<radio_connection::ConnError>,
}

impl<const GROUP_CAP: usize, const GROUP_LEN_CAP: usize, const FRAME_CAP: usize>
    RadioDriverCore<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP>
{
    pub(super) fn new(conn: RadioConnection<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP>) -> Self {
        Self {
            conn,
            rx_buf: [0u8; 512],
            rx_len: 0,
            tx_buf: [0u8; 64],
            tx_len: 0,
            phase: RadioDriverPhase::AwaitingPeerGreeting,
            error: None,
        }
    }

    pub(super) fn rx_slot(&mut self) -> &mut [u8] {
        &mut self.rx_buf[self.rx_len..]
    }

    pub(super) fn advance_rx(&mut self, n: usize) {
        self.rx_len += n;
    }

    pub(super) fn is_established(&self) -> bool {
        *self.conn.state() == radio_connection::State::Established
    }

    #[cfg(test)]
    pub(super) fn conn(&self) -> &RadioConnection<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP> {
        &self.conn
    }

    pub(super) fn publish_headers(
        &mut self,
        group: &[u8],
        body: &[u8],
    ) -> Result<Option<radio_connection::PublishHeaders>, radio_connection::ConnError> {
        self.conn.publish_headers(group, body)
    }

    pub(super) fn step(&mut self) -> Result<Action<'_>, radio_connection::ConnError> {
        loop {
            if self.tx_len > 0 {
                let len = self.tx_len;
                self.tx_len = 0;
                return Ok(Action::Write(&self.tx_buf[..len]));
            }

            match self.phase {
                RadioDriverPhase::SendingGreetingRest => {
                    self.phase = RadioDriverPhase::AwaitingPeerGreeting;
                    continue;
                }
                RadioDriverPhase::SendingReady => {
                    self.phase = RadioDriverPhase::AwaitingPeerReady;
                    continue;
                }
                RadioDriverPhase::Failed => {
                    return Err(self
                        .error
                        .take()
                        .unwrap_or(radio_connection::ConnError::WrongState));
                }
                _ => {}
            }

            match self.phase {
                RadioDriverPhase::AwaitingPeerGreeting => {
                    if *self.conn.state() == radio_connection::State::Ready {
                        let n = self.conn.write_ready(&mut self.tx_buf)?;
                        self.tx_len = n;
                        self.phase = RadioDriverPhase::SendingReady;
                        continue;
                    }

                    if self.rx_len == 0 {
                        return Ok(Action::Read);
                    }

                    let total_consumed = self.radio_feed_until_transition()?;
                    self.shift_rx(total_consumed);

                    if self.tx_len > 0 {
                        continue;
                    }
                    if self.rx_len > 0 {
                        return Ok(Action::Parked);
                    }
                    return Ok(Action::Read);
                }
                RadioDriverPhase::AwaitingPeerReady => {
                    if *self.conn.state() == radio_connection::State::Established {
                        self.phase = RadioDriverPhase::Established;
                        return Ok(Action::Established);
                    }
                    if self.rx_len == 0 {
                        return Ok(Action::Read);
                    }

                    let total_consumed = self.radio_feed_until_transition()?;
                    self.shift_rx(total_consumed);

                    if self.tx_len > 0 {
                        continue;
                    }
                    if *self.conn.state() == radio_connection::State::Established {
                        self.phase = RadioDriverPhase::Established;
                        return Ok(Action::Established);
                    }
                    if self.rx_len > 0 {
                        return Ok(Action::Parked);
                    }
                    return Ok(Action::Read);
                }
                RadioDriverPhase::Established => {
                    if self.rx_len == 0 {
                        return Ok(Action::Read);
                    }

                    let total_consumed = self.radio_feed_until_transition()?;
                    self.shift_rx(total_consumed);

                    if self.tx_len > 0 {
                        continue;
                    }
                    if self.rx_len > 0 {
                        return Ok(Action::Parked);
                    }
                    return Ok(Action::Read);
                }
                RadioDriverPhase::Failed
                | RadioDriverPhase::SendingGreetingRest
                | RadioDriverPhase::SendingReady => {
                    unreachable!()
                }
            }
        }
    }

    fn radio_feed_until_transition(&mut self) -> Result<usize, radio_connection::ConnError> {
        use radio_connection::State;
        let mut total_consumed = 0;
        while total_consumed < self.rx_len {
            let was_ready_before = *self.conn.state() == State::Ready;
            match self.conn.feed(&self.rx_buf[total_consumed..self.rx_len]) {
                Ok(consumed) => {
                    if consumed == 0 {
                        break;
                    }
                    total_consumed += consumed;

                    if self.conn.greeting_rest_pending() {
                        let n = self.conn.write_greeting_rest(&mut self.tx_buf)?;
                        self.tx_len = n;
                        self.phase = RadioDriverPhase::SendingGreetingRest;
                        break;
                    }

                    if *self.conn.state() == State::Ready && !was_ready_before {
                        let n = self.conn.write_ready(&mut self.tx_buf)?;
                        self.tx_len = n;
                        self.phase = RadioDriverPhase::SendingReady;
                        break;
                    }

                    let mut pong_buf = [0u8; 23];
                    if let Some(n) = self.conn.write_pong(&mut pong_buf)? {
                        self.tx_buf[..n].copy_from_slice(&pong_buf[..n]);
                        self.tx_len = n;
                        break;
                    }

                    if *self.conn.state() == State::Failed {
                        self.phase = RadioDriverPhase::Failed;
                        break;
                    }
                }
                Err(e) => {
                    if *self.conn.state() == State::Failed {
                        if let Ok(n) = self.conn.write_error(&mut self.tx_buf) {
                            self.tx_len = n;
                        }
                        self.phase = RadioDriverPhase::Failed;
                        self.error = Some(e);
                        break;
                    }
                    return Err(e);
                }
            }
        }
        Ok(total_consumed)
    }

    fn shift_rx(&mut self, consumed: usize) {
        if consumed > 0 {
            self.rx_buf.copy_within(consumed..self.rx_len, 0);
            self.rx_len -= consumed;
        }
    }
}

#[cfg(test)]
mod core_tests {
    use super::*;
    use crate::connection::State;
    use crate::test_helpers::{sub_greeting, sub_ready, sub_subscribe};

    extern crate alloc;

    fn make_core() -> DriverCore<8, 32, 512> {
        let mut conn = Connection::new();
        let mut buf = [0u8; 64];
        conn.write_greeting(&mut buf).unwrap();
        DriverCore::new_null(conn)
    }

    fn feed_all(core: &mut DriverCore<8, 32, 512>, data: &[u8]) {
        assert!(core.rx_len + data.len() <= 512);
        core.rx_buf[core.rx_len..core.rx_len + data.len()].copy_from_slice(data);
        core.rx_len += data.len();
    }

    #[test]
    fn core_null_handshake() {
        let mut core = make_core();

        assert!(matches!(core.step(), Ok(Action::Read)));

        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&sub_greeting());
        peer.extend_from_slice(&sub_ready());
        feed_all(&mut core, &peer);

        match core.step() {
            Ok(Action::Write(bytes)) => {
                assert_eq!(bytes.len(), 53);
            }
            other => panic!("expected Write(greeting_rest), got {other:?}"),
        }

        match core.step() {
            Ok(Action::Write(bytes)) => {
                assert_eq!(bytes[0], 0x04);
                assert_eq!(&bytes[3..8], b"READY");
            }
            other => panic!("expected Write(READY), got {other:?}"),
        }

        match core.step() {
            Ok(Action::Established) => {}
            other => panic!("expected Established, got {other:?}"),
        }

        assert_eq!(*core.conn.state(), State::Established);
    }

    #[test]
    fn core_feed_error_writes_error_frame() {
        let mut core = make_core();

        feed_all(&mut core, &sub_greeting());
        assert!(matches!(core.step(), Ok(Action::Write(_)))); // greeting_rest
        assert!(matches!(core.step(), Ok(Action::Write(_)))); // READY

        let push_ready = [
            0x04u8, 0x1A, 0x05, b'R', b'E', b'A', b'D', b'Y', 0x0B, b'S', b'o', b'c', b'k', b'e',
            b't', b'-', b'T', b'y', b'p', b'e', 0x00, 0x00, 0x00, 0x04, b'P', b'U', b'S', b'H',
        ];
        feed_all(&mut core, &push_ready);

        match core.step() {
            Ok(Action::Write(bytes)) => {
                assert_eq!(bytes[0], 0x04);
                assert_eq!(&bytes[3..8], b"ERROR");
            }
            other => panic!("expected Write(ERROR), got {other:?}"),
        }

        assert!(core.step().is_err());
        assert_eq!(*core.conn.state(), State::Failed);
    }

    #[test]
    fn core_chunked_greeting_completes_handshake() {
        let mut core = make_core();

        // Feed greeting in two chunks (first 11 bytes, then the rest)
        feed_all(&mut core, &sub_greeting()[..11]);
        feed_all(&mut core, &sub_greeting()[11..]);
        feed_all(&mut core, &sub_ready());

        // Process greeting_rest
        match core.step() {
            Ok(Action::Write(bytes)) => {
                assert_eq!(bytes.len(), 53);
            }
            other => panic!("expected Write(53), got {other:?}"),
        }

        // Write READY
        match core.step() {
            Ok(Action::Write(bytes)) => {
                assert_eq!(bytes[0], 0x04);
            }
            other => panic!("expected Write(READY), got {other:?}"),
        }

        // Established
        match core.step() {
            Ok(Action::Established) => {}
            other => panic!("expected Established, got {other:?}"),
        }

        assert_eq!(*core.conn.state(), State::Established);
    }

    #[test]
    fn core_subscribe_after_established() {
        let mut core = make_core();

        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&sub_greeting());
        peer.extend_from_slice(&sub_ready());
        peer.extend_from_slice(&sub_subscribe(b"foo"));
        feed_all(&mut core, &peer);

        assert!(matches!(core.step(), Ok(Action::Write(_)))); // greeting_rest
        assert!(matches!(core.step(), Ok(Action::Write(_)))); // READY
        assert!(matches!(core.step(), Ok(Action::Established)));

        assert!(matches!(core.step(), Ok(Action::Read)));

        let mut buf = [0u8; 256];
        let n = core.conn.publish(b"foo", b"data", &mut buf).unwrap();
        assert!(n > 0);
    }
}
