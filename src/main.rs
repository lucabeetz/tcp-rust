use std::io::prelude::*;
use std::{io, thread};

fn main() -> io::Result<()> {
    let mut i = tcprust::Interface::new()?;
    eprintln!("Created interface");
    let mut l = i.bind(9000)?;
    let jh = thread::spawn(move || {
        while let Ok(mut stream) = l.accept() {
            eprintln!("got connection");
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    eprintln!("no more data");
                    break;
                } else {
                    eprintln!("got {:?}", buf);
                }
            }
        }
    });
    jh.join().unwrap();
    Ok(())
}
