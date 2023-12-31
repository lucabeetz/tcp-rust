use bitflags::bitflags;
use std::collections::VecDeque;
use std::io;
use std::io::Write;

bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

pub enum State {
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::Closing | State::FinWait2 | State::TimeWait => {
                true
            }
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
}

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            true
        } else {
            false
        }
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }
        // TODO: set available WRITE
        a
    }
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
        let wnd = 1024;
        let mut c = Self {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss: iss,
                una: iss,
                nxt: iss,
                wnd: wnd,
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
            ip: etherparse::Ipv4Header::new(
                0,
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
            ),
            tcp: etherparse::TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                iss,
                10,
            ),
            incoming: VecDeque::new(),
            unacked: VecDeque::new(),
        };

        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, &[])?;
        Ok(Some(c))
    }

    fn write(
        &mut self,
        nic: &mut dyn tun::Device<Queue = tun::platform::Queue>,
        payload: &[u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len(),
        );
        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to checksum");

        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten)?;
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();

        // write packet flags and protocol first
        let mut new_buf = vec![0, 0, 0, 2];
        new_buf.extend_from_slice(&buf[..buf.len() - unwritten]);

        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        nic.write(&new_buf).unwrap();
        Ok(payload.len())
    }

    fn send_rst(
        &mut self,
        nic: &mut dyn tun::Device<Queue = tun::platform::Queue>,
    ) -> io::Result<()> {
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.ip.set_payload_len(self.tcp.header_len() as usize);
        self.write(nic, &[])?;
        Ok(())
    }

    pub fn on_packet(
        &mut self,
        nic: &mut dyn tun::Device<Queue = tun::platform::Queue>,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<Available> {
        // valid segment check
        // RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
        let seqn = tcp_header.sequence_number();
        let mut slen = data.len() as u32;
        if tcp_header.fin() {
            slen += 1;
        }
        if tcp_header.syn() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // zero length segment
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            self.write(nic, &[])?;
            return Ok(self.availability());
        }

        // if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
        //     && !is_between_wrapped(
        //         self.recv.nxt.wrapping_sub(1),
        //         seqn + data.len() as u32 - 1,
        //         wend,
        //     )
        // {
        //     return Ok(());
        // }
        // TODO: if not acceptable, send ACK

        if !tcp_header.ack() {
            if tcp_header.syn() {
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }

        let ackn = tcp_header.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                self.state = State::Estab;
            } else {
                // TODO: reset
            }
        }
        // terminate the connection
        // TODO: don't save it on the header, should only be set for last packet
        // self.tcp.fin = true;
        // self.write(nic, &[])?;
        // self.state = State::FinWait1;

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                self.send.una = ackn;
            }

            // TODO: only read what we haven't read yet
            // TODO: wake up awaiting readers

            if let State::Estab = self.state {
                // terminate the connection
                // TODO: don't save it on the header, should only be set for last packet
                self.tcp.fin = true;
                // self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                self.state = State::FinWait2;
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            let mut unread_data_at = (self.recv.nxt - seqn) as usize;
            if unread_data_at > data.len() {
                // must have received retransmitted FIN
                unread_data_at = 0;
            }

            // only read what we haven't read yet
            self.incoming.extend(&data[unread_data_at..]);

            self.recv.nxt = seqn
                .wrapping_add(data.len() as u32)
                .wrapping_add(if tcp_header.fin() { 1 } else { 0 });

            self.write(nic, &[])?;
        }

        if tcp_header.fin() {
            match self.state {
                State::FinWait2 => {
                    // done with connection
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(self.availability())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > 2 ^ 31
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
