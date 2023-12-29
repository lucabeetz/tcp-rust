use std::io;
use std::io::Read;

mod tcp;

fn main() -> io::Result<()> {
    let mut config = tun::Configuration::default();
    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let mut dev = tun::create(&config).unwrap();
    let mut buf = [0; 4096];

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

                        match connections.entry(Quad {
                            src: (src, tcp_header.source_port()),
                            dst: (dst, tcp_header.destination_port()),
                        }) {
                            Entry::Occupied(mut connection) => {
                                connection.get_mut().on_packet(
                                    &mut dev,
                                    ip_header,
                                    tcp_header,
                                    &buf[data_start..nbytes],
                                )?;
                            }
                            Entry::Vacant(e) => {
                                if let Some(connection) = tcp::Connection::accept(
                                    &mut dev,
                                    ip_header,
                                    tcp_header,
                                    &buf[data_start..nbytes],
                                )? {
                                    e.insert(connection);
                                }
                            }
                        }

                        // .or_default()
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
