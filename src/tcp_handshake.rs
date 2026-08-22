use std::io;
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use snow::HandshakeState;

use crate::DynError;
use crate::framing::{escrever_frame, ler_frame};
use crate::noise_lab::{
    HANDSHAKE_BUFFER_SIZE, ResultadoHandshake, criar_initiator, criar_responder,
    finalizar_handshake,
};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub fn executar_initiator(mut stream: TcpStream) -> Result<ResultadoHandshake, DynError> {
    stream.set_nodelay(true)?;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut estado = criar_initiator()?;
    let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
    let mut payload = [0_u8; HANDSHAKE_BUFFER_SIZE];

    // -> e
    let tamanho = estado.write_message(&[], &mut mensagem)?;
    escrever_frame(&mut stream, &mensagem[..tamanho], deadline)?;

    // <- e, ee, s, es
    let frame = ler_frame(&mut stream, deadline)?;
    let payload_2 = ler_payload_vazio(&mut estado, &frame, &mut payload)?;

    // -> s, se
    let tamanho = estado.write_message(&[], &mut mensagem)?;
    escrever_frame(&mut stream, &mensagem[..tamanho], deadline)?;

    let resultado = finalizar_handshake(estado, [0, payload_2, 0])?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(resultado)
}

pub fn executar_responder(mut stream: TcpStream) -> Result<ResultadoHandshake, DynError> {
    stream.set_nodelay(true)?;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut estado = criar_responder()?;
    let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
    let mut payload = [0_u8; HANDSHAKE_BUFFER_SIZE];

    // -> e
    let frame = ler_frame(&mut stream, deadline)?;
    let payload_1 = ler_payload_vazio(&mut estado, &frame, &mut payload)?;

    // <- e, ee, s, es
    let tamanho = estado.write_message(&[], &mut mensagem)?;
    escrever_frame(&mut stream, &mensagem[..tamanho], deadline)?;

    // -> s, se
    let frame = ler_frame(&mut stream, deadline)?;
    let payload_3 = ler_payload_vazio(&mut estado, &frame, &mut payload)?;

    let resultado = finalizar_handshake(estado, [payload_1, 0, payload_3])?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(resultado)
}

fn ler_payload_vazio(
    estado: &mut HandshakeState,
    frame: &[u8],
    payload: &mut [u8],
) -> Result<usize, DynError> {
    let tamanho = estado.read_message(frame, payload)?;
    if tamanho != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload de handshake deve ser vazio",
        )
        .into());
    }
    Ok(tamanho)
}
