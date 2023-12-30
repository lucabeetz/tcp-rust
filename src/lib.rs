use std::collections::{HashMap, VecDeque};
use std::io;
use std::io::prelude::*;
use std::net::Ipv4Addr;
use std::sync::Condvar;
use std::sync::{Arc, Mutex};
use std::thread;

mod tcp;

const SENDQUEUE_SIZE: usize = 1024;

type InterfaceHandle = Arc<Foobar>;

#[derive(Default)]
struct Foobar {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    rcv_var: Condvar,
}

pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

struct Pending {
    quads: VecDeque<Quad>,
    var: Condvar,
}

#[derive(Default)]
struct ConnectionManager {
    terminate: bool,
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

fn packet_loop(mut dev: tun::platform::Device, ih: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = dev.read(&mut buf)?;
        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        if eth_proto != 0x0002 {
            // Ignore non-IPv4 packets
            // note that macos uses different values for AF_INET and AF_INET6
            // https://github.com/meh/rust-tun/issues/58
            // https://opensource.apple.com/source/xnu/xnu-201/bsd/sys/socket.h
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();
                if ip_header.protocol() != 0x06 {
                    // Ignore non-TCP packets
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[4 + ip_header.slice().len()..nbytes],
                ) {
                    Ok(tcp_header) => {
                        use std::collections::hash_map::Entry;
                        let data_start = 4 + ip_header.slice().len() + tcp_header.slice().len();
                        let mut cmg = ih.manager.lock().unwrap();
                        let cm = &mut *cmg;
                        let q = Quad {
                            src: (src, tcp_header.source_port()),
                            dst: (dst, tcp_header.destination_port()),
                        };

                        match cm.connections.entry(Quad {
                            src: (src, tcp_header.source_port()),
                            dst: (dst, tcp_header.destination_port()),
                        }) {
                            Entry::Occupied(mut connection) => {
                                let a = connection.get_mut().on_packet(
                                    &mut dev,
                                    ip_header,
                                    tcp_header,
                                    &buf[data_start..nbytes],
                                )?;

                                drop(cm);
                                if a.contains(tcp::Available::READ) {
                                    ih.rcv_var.notify_all();
                                }
                                if a.contains(tcp::Available::WRITE) {
                                    // TODO
                                }
                            }
                            Entry::Vacant(e) => {
                                if let Some(pending) =
                                    cm.pending.get_mut(&tcp_header.destination_port())
                                {
                                    if let Some(c) = tcp::Connection::accept(
                                        &mut dev,
                                        ip_header,
                                        tcp_header,
                                        &buf[data_start..nbytes],
                                    )? {
                                        e.insert(c);
                                        pending.push_back(q);
                                        drop(cmg);
                                        ih.pending_var.notify_all();
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Ignoring malformed TCP packet: {:?}", e)
                    }
                }
            }
            Err(e) => {
                eprintln!("Ignoring malformed IPv4 packet: {:?}", e)
            }
        }
    }
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let mut config = tun::Configuration::default();
        config
            .address((10, 0, 0, 1))
            .netmask((255, 255, 255, 0))
            .up();
        let mut dev = tun::create(&config).unwrap();

        let ih: InterfaceHandle = Arc::default();

        let jh = {
            let ih = ih.clone();
            thread::spawn(move || packet_loop(dev, ih))
        };

        Ok(Interface {
            ih: Some(ih),
            jh: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;

        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already in use",
                ))
            }
        }
        drop(cm);
        Ok(TcpListener(port, self.ih.as_mut().unwrap().clone()))
    }
}

pub struct TcpStream(Quad, InterfaceHandle);

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut cm = self.1.manager.lock().unwrap();
        if let Some(c) = cm.connections.remove(&self.0) {
            // TODO: Send FIN
            unimplemented!()
        }
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.1.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "connection not found")
        })?;

        if c.is_rcv_closed() && c.incoming.is_empty() {
            // no more data to read and connection is closed, no need to block
            return Ok(0);
        }
        if !c.incoming.is_empty() {
            let mut nread = 0;
            let (head, tail) = c.incoming.as_slices();
            let hread = std::cmp::min(buf.len(), head.len());
            buf.copy_from_slice(&head[..hread]);
            nread += hread;
            let tread = std::cmp::min(buf.len() - nread, tail.len());
            buf.copy_from_slice(&tail[..tread]);
            nread += tread;
            drop(c.incoming.drain(..nread));
            return Ok(nread);
        }

        cm = self.1.rcv_var.wait(cm).unwrap();
        Ok(0)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.1.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "connection not found")
        })?;

        if c.unacked.len() >= SENDQUEUE_SIZE {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "connection buffer full",
            ));
        }

        let nwrite = std::cmp::min(buf.len(), SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(buf[..nwrite].iter());
        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.1.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "connection not found")
        })?;

        if c.unacked.is_empty() {
            return Ok(());
        } else {
            // TODO: block
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "connection buffer full",
            ))
        }
    }
}

pub struct TcpListener(u16, InterfaceHandle);

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.1.manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.0)
            .expect("port closed while listener active");

        for quad in pending {
            unimplemented!()
        }
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.1.manager.lock().unwrap();
        if let Some(quad) = cm.pending.get_mut(&self.0).unwrap().pop_front() {
            return Ok(TcpStream(quad, self.1.clone()));
        } else {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no pending connections",
            ));
        }
    }
}
