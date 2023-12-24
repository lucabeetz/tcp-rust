use std::io;
use std::io::Read;

fn main() -> io::Result<()> {
    let mut config = tun::Configuration::default();
    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let mut dev = tun::create(&config).unwrap();
    let mut buf = [0; 4096];

    loop {
        let amount = dev.read(&mut buf)?;
        let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        if eth_proto != 0x0002 {
            // Ignore non-IPv4 packets
            // note that macos uses different values for AF_INET and AF_INET6
            // https://github.com/meh/rust-tun/issues/58
            // https://opensource.apple.com/source/xnu/xnu-201/bsd/sys/socket.h
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..amount]) {
            Ok(p) => {
                let src = p.source_addr();
                let dst = p.destination_addr();
                let proto = p.protocol();
                if proto != 0x06 {
                    // Ignore non-TCP packets
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + p.slice().len()..]) {
                    Ok(p) => {
                        let src_port = p.source_port();
                        let dst_port = p.destination_port();
                        eprintln!(
                            "{}:{} -> {}:{} (payload: {} bytes)",
                            src,
                            src_port,
                            dst,
                            dst_port,
                            p.slice().len()
                        );
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
