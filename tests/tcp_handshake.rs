use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use securechat::framing::escrever_frame;
use securechat::noise_lab::{HANDSHAKE_BUFFER_SIZE, criar_initiator};
use securechat::tcp_handshake::{executar_initiator, executar_responder};

fn listener_local() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").expect("listener loopback")
}

#[test]
fn handshake_tcp_completo_produz_channel_binding_e_fingerprint_iguais() {
    let listener = listener_local();
    let endereco = listener.local_addr().expect("endereço local");
    let responder = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        executar_responder(stream).expect("handshake responder")
    });

    let initiator = executar_initiator(TcpStream::connect(endereco).expect("connect"))
        .expect("handshake initiator");
    let responder = responder.join().expect("thread responder");

    assert_eq!(initiator.handshake_hash().len(), 32);
    assert_eq!(responder.handshake_hash().len(), 32);
    assert_eq!(initiator.handshake_hash(), responder.handshake_hash());
    assert_eq!(initiator.fingerprint(), responder.fingerprint());
    assert!(initiator.payloads_vazios());
    assert!(responder.payloads_vazios());
}

#[test]
fn encerramento_antes_do_handshake_nao_produz_resultado() {
    let listener = listener_local();
    let endereco = listener.local_addr().expect("endereço local");
    let responder = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        executar_responder(stream)
    });

    let stream = TcpStream::connect(endereco).expect("connect");
    drop(stream);

    assert!(responder.join().expect("thread responder").is_err());
}

#[test]
fn truncamento_durante_frame_nao_produz_resultado() {
    let listener = listener_local();
    let endereco = listener.local_addr().expect("endereço local");
    let responder = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        executar_responder(stream)
    });

    let mut stream = TcpStream::connect(endereco).expect("connect");
    stream.write_all(&32_u32.to_be_bytes()).expect("prefixo");
    stream.write_all(&[0_u8; 5]).expect("body parcial");
    stream.shutdown(Shutdown::Write).expect("shutdown");

    assert!(responder.join().expect("thread responder").is_err());
}

#[test]
fn interrupcao_apos_primeira_mensagem_nao_produz_fingerprint() {
    let listener = listener_local();
    let endereco = listener.local_addr().expect("endereço local");
    let responder = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        executar_responder(stream)
    });

    let mut stream = TcpStream::connect(endereco).expect("connect");
    let mut alice = criar_initiator().expect("Alice");
    let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
    let tamanho = alice.write_message(&[], &mut mensagem).expect("mensagem 1");
    escrever_frame(
        &mut stream,
        &mensagem[..tamanho],
        Instant::now() + Duration::from_secs(2),
    )
    .expect("frame 1");
    stream.shutdown(Shutdown::Both).expect("shutdown");

    assert!(responder.join().expect("thread responder").is_err());
}

#[test]
fn payload_noise_nao_vazio_e_rejeitado() {
    let listener = listener_local();
    let endereco = listener.local_addr().expect("endereço local");
    let responder = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        executar_responder(stream)
    });

    let mut stream = TcpStream::connect(endereco).expect("connect");
    let mut alice = criar_initiator().expect("Alice");
    let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
    let tamanho = alice
        .write_message(b"payload proibido", &mut mensagem)
        .expect("mensagem com payload");
    escrever_frame(
        &mut stream,
        &mensagem[..tamanho],
        Instant::now() + Duration::from_secs(2),
    )
    .expect("frame");

    assert!(responder.join().expect("thread responder").is_err());
}
