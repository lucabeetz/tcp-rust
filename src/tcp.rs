use bitflags::bitflags;
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::{io, time};

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

    fn have_sent_fin(&self) -> bool {
        match self {
            State::SynRcvd | State::Estab => false,
            State::FinWait1 | State::Closing | State::FinWait2 | State::TimeWait => true,
        }
    }
}

pub struct Connection {
    pub(crate) state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,

    timers: Timers,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
    pub(crate) closed: bool,
    closed_at: Option<u32>,
}

struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    srtt: f64,
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
            closed: false,
            closed_at: None,
            timers: Timers {
                send_times: Default::default(),
                srtt: time::Duration::from_secs(60).as_secs_f64(),
            },
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
        c.write(nic, c.send.nxt, 0)?;
        Ok(Some(c))
    }

    fn write(
        &mut self,
        nic: &mut dyn tun::Device<Queue = tun::platform::Queue>,
        seq: u32,
        mut limit: usize,
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.recv.nxt;

        // special case the virtual bytes SYN and FIN
        let mut offset = seq.wrapping_sub(self.send.una) as usize;
        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                offset = 0;
                limit = 0;
            }
        }

        let (mut h, mut t) = self.unacked.as_slices();
        if h.len() >= offset {
            h = &h[offset..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }

        let max_data = std::cmp::min(limit, h.len() + t.len());
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + max_data,
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

        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            let pl1 = std::cmp::min(limit, h.len());
            written += unwritten.write(&h[..pl1])?;
            limit -= written;

            let pl2 = std::cmp::min(limit, t.len());
            written += unwritten.write(&t[..pl2])?;
            written
        };

        let unwritten = unwritten.len();
        let mut next_seq = seq.wrapping_add(payload_bytes as u32);

        // write packet flags and protocol first
        let mut new_buf = vec![0, 0, 0, 2];
        new_buf.extend_from_slice(&buf[..buf.len() - unwritten]);

        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }

        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }
        self.timers.send_times.insert(seq, time::Instant::now());

        nic.write(&new_buf).unwrap();
        Ok(payload_bytes)
    }

    fn send_rst(
        &mut self,
        nic: &mut dyn tun::Device<Queue = tun::platform::Queue>,
    ) -> io::Result<()> {
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, self.send.nxt, 0)?;
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
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

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

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                if !self.unacked.is_empty() {
                    let data_start = if self.send.una == self.send.iss {
                        self.send.una.wrapping_add(1)
                    } else {
                        self.send.una
                    };
                    let acked_data_end =
                        std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());
                    self.unacked.drain(..acked_data_end);

                    self.timers.send_times.retain(|&seq, sent| {
                        if is_between_wrapped(self.send.una, seq, ackn) {
                            let rtt = sent.elapsed();
                            self.timers.srtt =
                                0.8 * self.timers.srtt + (1.0 - 0.8) * rtt.as_secs_f64();
                            false
                        } else {
                            true
                        }
                    });
                }
                self.send.una = ackn;
            }

            // TODO: only read what we haven't read yet
            // TODO: wake up awaiting readers
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                self.state = State::FinWait2;
            }
        }

        if !data.is_empty() {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                let mut unread_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;
                if unread_data_at > data.len() {
                    // must have received retransmitted FIN
                    unread_data_at = 0;
                }

                // only read what we haven't read yet
                self.incoming.extend(&data[unread_data_at..]);

                self.recv.nxt = seqn.wrapping_add(data.len() as u32);

                self.write(nic, self.send.nxt, 0)?;
            }
        }

        if tcp_header.fin() {
            match self.state {
                State::FinWait2 => {
                    // done with connection
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(self.availability())
    }

    pub(crate) fn on_tick(
        &mut self,
        dev: &mut dyn tun::Device<Queue = tun::platform::Queue>,
    ) -> io::Result<()> {
        let nunacked = self
            .closed_at
            .unwrap_or(self.send.nxt)
            .wrapping_sub(self.send.una);
        let nunsent = self.unacked.len() as u32 - nunacked;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|(_, t)| t.elapsed());

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            // should retransmit
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed {
                // should we resend FIN
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            let (h, t) = self.unacked.as_slices();
            self.write(dev, self.send.una, resend as usize)?;
            self.send.nxt = self.send.una.wrapping_add(resend);
        } else {
            // send new data if new data available and space in window
            if nunsent == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd as u32 - nunacked;
            if allowed == 0 {
                return Ok(());
            }

            let send = std::cmp::min(nunsent, allowed);
            if send < allowed && self.closed && self.closed_at.is_none() {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.nxt.wrapping_add(nunsent as u32));
            }

            self.write(dev, self.send.nxt, send as usize)?;
        }

        Ok(())
    }

    pub(crate) fn close(&mut self) {
        self.closed = true;
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > 2 ^ 31
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
