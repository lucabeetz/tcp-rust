use std::io;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
}

/// Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
/// 1         2          3          4
/// ----------|----------|----------|----------
///   SND.UNA    SND.NXT    SND.UNA
///                        +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
struct SendSequenceSpace {
    /// send unacknowledged
    una: usize,
    /// send next
    nxt: usize,
    /// send window
    wnd: usize,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: usize,
}

/// Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```
/// 1          2          3
/// ----------|----------|----------
///    RCV.NXT    RCV.NXT
///              +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct ReceiveSequenceSpace {
    /// receive next
    nxt: usize,
    /// receive window
    wnd: usize,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: usize,
}

impl Default for Connection {
    fn default() -> Self {
        // State::Closed,
        Self {
            state: State::Listen,
        }
    }
}

impl Connection {
    pub fn on_packet(
        &self,
        nic: &mut dyn tun::Device<Queue = tun::platform::Queue>,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<()> {
        let mut buf = [0u8; 1500];

        match self.state {
            State::Closed => return Ok(()),
            State::Listen => {
                if !tcp_header.syn() {
                    // only expect SYN packet
                    return Ok(());
                }

                // send SYN-ACK
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    0,
                    0,
                );
                syn_ack.syn = true;
                syn_ack.ack = true;

                let ip = etherparse::Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    etherparse::IpNumber::Tcp as u8,
                    [
                        ip_header.destination()[0],
                        ip_header.destination()[1],
                        ip_header.destination()[2],
                        ip_header.destination()[3],
                    ],
                    [
                        ip_header.source()[0],
                        ip_header.source()[1],
                        ip_header.source()[2],
                        ip_header.source()[3],
                    ],
                );

                // write headers
                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    ip.write(&mut unwritten);
                    syn_ack.write(&mut unwritten);
                    unwritten.len()
                };
                nic.write(&buf[..unwritten]).unwrap();
            }
            _ => return Ok(()),
        }
        eprintln!(
            "{}:{} -> {}:{} (payload: {} bytes)",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len()
        );

        Ok(())
    }
}
