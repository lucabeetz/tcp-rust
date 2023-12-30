use std::io::prelude::*;
use std::{io, thread};

fn main() -> io::Result<()> {
    let mut i = tcprust::Interface::new()?;
    eprintln!("Created interface");
    let mut l1 = i.bind(9000)?;
    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection");
            let n = stream.read(&mut [0]).unwrap();
            eprintln!("read {} bytes", n);
        }
    });
    jh1.join().unwrap();
    Ok(())
}
