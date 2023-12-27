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
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number
    iss: u32,
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
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept(
        nic: &mut dyn tun::Device<Queue = tun::platform::Queue>,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcp_header.syn() {
            // only expect SYN packet
            return Ok(None);
        }

        let iss = 0;
        let mut c = Self {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss: iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: ReceiveSequenceSpace {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                up: false,
            },
        };

        // send SYN-ACK
        let mut syn_ack = etherparse::TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            c.send.iss,
            c.send.wnd,
        );
        syn_ack.acknowledgment_number = c.recv.nxt;
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

        syn_ack.checksum = syn_ack
            .calc_checksum_ipv4(&ip, &[])
            .expect("failed to calculate checksum");

        // write headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            ip.write(&mut unwritten);
            syn_ack.write(&mut unwritten);
            unwritten.len()
        };
        // send flags and proto first (again 0x2 because of macos)
        let mut new_buf = vec![0, 0, 0, 2];
        new_buf.extend_from_slice(&buf[..buf.len() - unwritten]);
        nic.write(&new_buf).unwrap();

        eprintln!("responding with {:02x?}", &buf[..buf.len() - unwritten]);

        Ok(Some(c))
    }
    pub fn on_packet(
        &mut self,
        nic: &mut dyn tun::Device<Queue = tun::platform::Queue>,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        Ok(0)
    }
}
