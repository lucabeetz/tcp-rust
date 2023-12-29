use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

mod tcp;

type InterfaceHandle = mpsc::Sender<InterfaceRequest>;

enum InterfaceRequest {
    Write {
        quad: Quad,
        bytes: Vec<u8>,
        ack: mpsc::Sender<usize>,
    },
    Flush {
        quad: Quad,
        ack: mpsc::Sender<()>,
    },
    Bind {
        port: u16,
        ack: mpsc::Sender<()>,
    },
    Unbind,
    Read {
        quad: Quad,
        max_length: usize,
        read: mpsc::Sender<Vec<u8>>,
    },
    Accept {
        port: u16,
        ack: mpsc::Sender<Quad>,
    },
}

pub struct Interface {
    tx: mpsc::Sender<InterfaceRequest>,
    jh: thread::JoinHandle<()>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}
struct ConnectionManager {
    connections: HashMap<Quad, tcp::Connection>,
    buf: [u8; 4096],
    dev: tun::platform::Device,
}

impl ConnectionManager {
    fn run_on(&mut self, rx: mpsc::Receiver<InterfaceRequest>) {
        for req in rx {}
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
        let mut buf = [0; 4096];

        let mut cm = ConnectionManager {
            connections: Default::default(),
            buf,
            dev,
        };

        let (tx, rx) = mpsc::channel();
        let jh = thread::spawn(move || {
            cm.run_on(rx);
        });
        Ok(Interface { tx, jh })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let (ack, rx) = mpsc::channel();
        self.tx.send(InterfaceRequest::Bind { port, ack });
        rx.recv().unwrap();

        Ok(TcpListener(port, self.tx.clone()))
    }
}

pub struct TcpStream(Quad, InterfaceHandle);

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (read, rx) = mpsc::channel();
        self.1.send(InterfaceRequest::Read {
            quad: self.0,
            max_length: buf.len(),
            read,
        });
        let bytes = rx.recv().unwrap();
        buf.copy_from_slice(&bytes[..]);
        Ok(bytes.len())
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (ack, rx) = mpsc::channel();
        self.1.send(InterfaceRequest::Write {
            quad: self.0,
            bytes: buf.to_vec(),
            ack,
        });
        let n = rx.recv().unwrap();
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let (ack, rx) = mpsc::channel();
        self.1.send(InterfaceRequest::Flush { quad: self.0, ack });
        rx.recv().unwrap();
        Ok(())
    }
}

pub struct TcpListener(u16, InterfaceHandle);

impl TcpListener {
    fn accept(&mut self) -> io::Result<TcpStream> {
        let (ack, rx) = mpsc::channel();
        self.1.send(InterfaceRequest::Accept { port: self.0, ack });
        let quad = rx.recv().unwrap();
        Ok(TcpStream(quad, self.1.clone()))
    }
}
