use std::io::prelude::*;
use std::{io, thread};

fn main() -> io::Result<()> {
    let mut interface = tcprust::Interface::new()?;
    eprintln!("Created interface");
    let mut listener = interface.bind(9001)?;

    while let Ok(mut stream) = listener.accept() {
        thread::spawn(move || {
            stream.write(b"Hello World").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    eprintln!("no more data");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        });
    }

    Ok(())
}
