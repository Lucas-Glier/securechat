use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub const MAX_FRAME_BODY: usize = 8192;
pub const FRAME_PROGRESS_TIMEOUT: Duration = Duration::from_secs(15);

pub fn codificar_tamanho(tamanho: usize) -> Result<[u8; 4], io::Error> {
    validar_tamanho(tamanho)?;
    Ok((tamanho as u32).to_be_bytes())
}

fn validar_tamanho(tamanho: usize) -> Result<(), io::Error> {
    if !(1..=MAX_FRAME_BODY).contains(&tamanho) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "comprimento de frame fora de 1..=8192",
        ));
    }
    Ok(())
}

pub fn escrever_frame(
    stream: &mut TcpStream,
    body: &[u8],
    deadline: Instant,
) -> Result<(), io::Error> {
    let prefixo = codificar_tamanho(body.len())?;
    escrever_exato_ate(stream, &prefixo, deadline)?;
    escrever_exato_ate(stream, body, deadline)
}

pub fn ler_frame(
    stream: &mut TcpStream,
    deadline_handshake: Instant,
) -> Result<Vec<u8>, io::Error> {
    let mut prefixo = [0_u8; 4];
    ler_exato_ate(
        stream,
        &mut prefixo[..1],
        deadline_handshake,
        "conexão encerrada antes do prefixo do frame",
    )?;

    ler_frame_apos_primeiro_byte(stream, prefixo, deadline_handshake)
}

/// Aguarda o início de um frame sem fixar o deadline da fase da sessão.
///
/// O proprietário da sessão controla essa espera fechando o socket quando seu
/// deadline expira. Depois do primeiro byte, o prazo fixo de progresso do frame
/// é aplicado e não pode ser renovado por atividade local ou outros eventos.
pub fn ler_frame_sessao(stream: &mut TcpStream) -> Result<Vec<u8>, io::Error> {
    stream.set_read_timeout(None)?;
    let mut prefixo = [0_u8; 4];
    loop {
        match stream.read(&mut prefixo[..1]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "conexão encerrada antes do prefixo do frame",
                ));
            }
            Ok(_) => break,
            Err(erro) if erro.kind() == io::ErrorKind::Interrupted => continue,
            Err(erro) => return Err(erro),
        }
    }

    ler_frame_apos_primeiro_byte(stream, prefixo, Instant::now() + FRAME_PROGRESS_TIMEOUT)
}

fn ler_frame_apos_primeiro_byte(
    stream: &mut TcpStream,
    mut prefixo: [u8; 4],
    deadline_fase: Instant,
) -> Result<Vec<u8>, io::Error> {
    let deadline_frame = Instant::now() + FRAME_PROGRESS_TIMEOUT;
    let deadline_efetivo = deadline_fase.min(deadline_frame);
    ler_exato_ate(
        stream,
        &mut prefixo[1..],
        deadline_efetivo,
        "prefixo de frame truncado",
    )?;

    let tamanho = u32::from_be_bytes(prefixo) as usize;
    validar_tamanho(tamanho)?;

    // A alocação só ocorre depois de validar o limite controlado pelo peer.
    let mut body = vec![0_u8; tamanho];
    ler_exato_ate(
        stream,
        &mut body,
        deadline_efetivo,
        "body de frame truncado",
    )?;
    Ok(body)
}

fn ler_exato_ate(
    stream: &mut TcpStream,
    mut destino: &mut [u8],
    deadline: Instant,
    mensagem_eof: &'static str,
) -> Result<(), io::Error> {
    while !destino.is_empty() {
        stream.set_read_timeout(Some(tempo_restante(deadline)?))?;
        match stream.read(destino) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, mensagem_eof)),
            Ok(lidos) => destino = &mut destino[lidos..],
            Err(erro) if erro.kind() == io::ErrorKind::Interrupted => continue,
            Err(erro)
                if matches!(
                    erro.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "deadline de leitura do frame excedido",
                ));
            }
            Err(erro) => return Err(erro),
        }
    }
    Ok(())
}

fn escrever_exato_ate(
    stream: &mut TcpStream,
    mut origem: &[u8],
    deadline: Instant,
) -> Result<(), io::Error> {
    while !origem.is_empty() {
        stream.set_write_timeout(Some(tempo_restante(deadline)?))?;
        match stream.write(origem) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "não foi possível concluir a escrita do frame",
                ));
            }
            Ok(escritos) => origem = &origem[escritos..],
            Err(erro) if erro.kind() == io::ErrorKind::Interrupted => continue,
            Err(erro)
                if matches!(
                    erro.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "deadline de escrita do frame excedido",
                ));
            }
            Err(erro) => return Err(erro),
        }
    }
    stream.flush()
}

fn tempo_restante(deadline: Instant) -> Result<Duration, io::Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duracao| !duracao.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline excedido"))
}

#[cfg(test)]
mod tests {
    use std::net::{Shutdown, TcpListener};
    use std::thread;

    use super::*;

    fn par_tcp() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener local");
        let endereco = listener.local_addr().expect("endereço local");
        let cliente = TcpStream::connect(endereco).expect("conexão local");
        let (servidor, _) = listener.accept().expect("accept local");
        (cliente, servidor)
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    #[test]
    fn codifica_prefixo_u32_em_big_endian() {
        assert_eq!(codificar_tamanho(1).expect("tamanho válido"), [0, 0, 0, 1]);
        assert_eq!(
            codificar_tamanho(8192).expect("tamanho válido"),
            [0, 0, 0x20, 0]
        );
    }

    #[test]
    fn rejeita_frame_de_tamanho_zero() {
        assert_eq!(
            codificar_tamanho(0).expect_err("zero deve falhar").kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejeita_frame_de_8193_bytes() {
        assert_eq!(
            codificar_tamanho(8193)
                .expect_err("8193 deve falhar")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejeita_prefixo_truncado() {
        let (mut cliente, mut servidor) = par_tcp();
        cliente.write_all(&[0, 0]).expect("prefixo parcial");
        cliente.shutdown(Shutdown::Write).expect("shutdown");

        assert_eq!(
            ler_frame(&mut servidor, deadline())
                .expect_err("prefixo truncado deve falhar")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn rejeita_body_truncado() {
        let (mut cliente, mut servidor) = par_tcp();
        cliente.write_all(&5_u32.to_be_bytes()).expect("prefixo");
        cliente.write_all(&[1, 2]).expect("body parcial");
        cliente.shutdown(Shutdown::Write).expect("shutdown");

        assert_eq!(
            ler_frame(&mut servidor, deadline())
                .expect_err("body truncado deve falhar")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn leitura_parcial_aguarda_frame_completo() {
        let (mut cliente, mut servidor) = par_tcp();
        let escritor = thread::spawn(move || {
            for byte in [0_u8, 0, 0, 3, 7, 8, 9] {
                cliente.write_all(&[byte]).expect("byte parcial");
                thread::sleep(Duration::from_millis(2));
            }
        });

        assert_eq!(
            ler_frame(&mut servidor, deadline()).expect("frame completo"),
            vec![7, 8, 9]
        );
        escritor.join().expect("thread escritora");
    }

    #[test]
    fn dois_frames_consecutivos_sao_lidos_separadamente() {
        let (mut cliente, mut servidor) = par_tcp();
        escrever_frame(&mut cliente, &[1, 2], deadline()).expect("primeiro frame");
        escrever_frame(&mut cliente, &[3, 4, 5], deadline()).expect("segundo frame");

        assert_eq!(ler_frame(&mut servidor, deadline()).unwrap(), vec![1, 2]);
        assert_eq!(ler_frame(&mut servidor, deadline()).unwrap(), vec![3, 4, 5]);
    }

    #[test]
    fn leitura_de_sessao_aguarda_primeiro_byte_e_entrega_frame_completo() {
        let (mut cliente, mut servidor) = par_tcp();
        let escritor = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            cliente.write_all(&[0]).unwrap();
            for byte in [0_u8, 0, 2, 8, 9] {
                thread::sleep(Duration::from_millis(2));
                cliente.write_all(&[byte]).unwrap();
            }
        });

        assert_eq!(ler_frame_sessao(&mut servidor).unwrap(), vec![8, 9]);
        escritor.join().unwrap();
    }
}
