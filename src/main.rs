use std::env;
use std::io;
use std::net::{TcpListener, TcpStream};

use securechat::DynError;
use securechat::address::{ModoExecucao, erro_publico_rede, parse_endereco_local};
use securechat::tcp_handshake::{executar_initiator, executar_responder};
use securechat::verification::executar_verificacao_interativa;

const USO: &str =
    "Uso:\n  securechat listen <ip-loopback:porta>\n  securechat connect <ip-loopback:porta>";

fn main() -> Result<(), DynError> {
    let mut argumentos = env::args().skip(1);
    let modo: ModoExecucao = argumentos
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USO))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, USO))?;
    let endereco = parse_endereco_local(
        &argumentos
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USO))?,
    )
    .map_err(|erro| io::Error::new(io::ErrorKind::InvalidInput, format!("{erro}\n\n{USO}")))?;

    if argumentos.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, USO).into());
    }

    let resultado = match modo {
        ModoExecucao::Listen => {
            let listener = TcpListener::bind(endereco).map_err(erro_publico_rede)?;
            let (stream, _) = listener.accept().map_err(erro_publico_rede)?;
            executar_responder(stream)?
        }
        ModoExecucao::Connect => {
            let stream =
                TcpStream::connect_timeout(&endereco, securechat::tcp_handshake::HANDSHAKE_TIMEOUT)
                    .map_err(erro_publico_rede)?;
            executar_initiator(stream)?
        }
    };

    println!("Handshake Noise XX concluído.");
    executar_verificacao_interativa(resultado)?;

    Ok(())
}
