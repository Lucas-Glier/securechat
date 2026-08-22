use std::env;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};

use securechat::DynError;
use securechat::tcp_handshake::{executar_initiator, executar_responder};

const USO: &str =
    "Uso:\n  securechat listen <ip-loopback:porta>\n  securechat connect <ip-loopback:porta>";

fn main() -> Result<(), DynError> {
    let mut argumentos = env::args().skip(1);
    let modo = argumentos
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USO))?;
    let endereco: SocketAddr = argumentos
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USO))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, USO))?;

    if argumentos.next().is_some() || !endereco.ip().is_loopback() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, USO).into());
    }

    let resultado = match modo.as_str() {
        "listen" => {
            let listener = TcpListener::bind(endereco)?;
            let (stream, _) = listener.accept()?;
            executar_responder(stream)?
        }
        "connect" => {
            let stream = TcpStream::connect_timeout(
                &endereco,
                securechat::tcp_handshake::HANDSHAKE_TIMEOUT,
            )?;
            executar_initiator(stream)?
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, USO).into()),
    };

    println!("Handshake Noise XX concluído.");
    println!("Estado: UNVERIFIED");
    println!("Fingerprint: {}", resultado.fingerprint());

    Ok(())
}
