use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::thread;

use securechat::address::{
    ModoExecucao, PapelNoise, mensagem_erro_rede, parse_endereco_local, validar_endereco_local,
};
use securechat::tcp_handshake::{executar_initiator, executar_responder};
use securechat::verification::{EstadoSessao, SessaoVerificacao};

fn aceita(valor: &str) {
    assert!(
        parse_endereco_local(valor).is_ok(),
        "deveria aceitar {valor}"
    );
}

fn rejeita(valor: &str) {
    assert!(
        parse_endereco_local(valor).is_err(),
        "deveria rejeitar {valor}"
    );
}

#[test]
fn aceita_ipv4_loopback_e_privado() {
    for endereco in [
        "127.0.0.1:7777",
        "127.20.30.40:7777",
        "10.0.0.1:7777",
        "10.255.255.254:7777",
        "172.16.0.1:7777",
        "172.31.255.254:7777",
        "192.168.0.1:7777",
        "192.168.255.254:7777",
    ] {
        aceita(endereco);
    }
}

#[test]
fn aceita_ipv6_loopback_e_ula() {
    for endereco in [
        "[::1]:7777",
        "[fc00::1]:7777",
        "[fd12:3456:789a::1]:7777",
        "[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:7777",
    ] {
        aceita(endereco);
    }
}

#[test]
fn rejeita_unspecified_link_local_publico_global_multicast_e_broadcast() {
    for endereco in [
        "0.0.0.0:7777",
        "[::]:7777",
        "169.254.10.20:7777",
        "[fe80::1]:7777",
        "8.8.8.8:7777",
        "[2001:4860:4860::8888]:7777",
        "224.0.0.1:7777",
        "[ff02::1]:7777",
        "255.255.255.255:7777",
    ] {
        rejeita(endereco);
    }
}

#[test]
fn rejeita_documentacao_testnet_porta_zero_e_hostname() {
    for endereco in [
        "192.0.2.1:7777",
        "198.51.100.1:7777",
        "203.0.113.1:7777",
        "[2001:db8::1]:7777",
        "127.0.0.1:0",
        "192.168.1.20:0",
        "localhost:7777",
        "peer.exemplo:7777",
    ] {
        rejeita(endereco);
    }
}

#[test]
fn connect_e_initiator_e_listen_e_responder() {
    assert_eq!(
        "connect".parse::<ModoExecucao>().unwrap().papel_noise(),
        PapelNoise::Initiator
    );
    assert_eq!(
        "listen".parse::<ModoExecucao>().unwrap().papel_noise(),
        PapelNoise::Responder
    );
    assert!("outro".parse::<ModoExecucao>().is_err());
}

#[test]
fn endereco_validado_nao_autentica_peer_nem_altera_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endereco = listener.local_addr().unwrap();
    validar_endereco_local(endereco).unwrap();

    let responder = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        executar_responder(stream).unwrap()
    });
    let initiator = executar_initiator(TcpStream::connect(endereco).unwrap()).unwrap();
    let responder = responder.join().unwrap();

    assert_eq!(initiator.handshake_hash(), responder.handshake_hash());
    let (_, canal_initiator) = initiator.into_parts();
    let (_, canal_responder) = responder.into_parts();
    let initiator = SessaoVerificacao::new(canal_initiator);
    let responder = SessaoVerificacao::new(canal_responder);

    for sessao in [&initiator, &responder] {
        assert_eq!(sessao.estado(), EstadoSessao::Unverified);
        assert!(!sessao.local_confirmed());
        assert!(!sessao.peer_confirmed());
    }
}

#[test]
fn classifica_erros_publicos_de_rede_sem_contexto_sensivel() {
    let casos = [
        (
            io::ErrorKind::ConnectionRefused,
            "conexão recusada pelo peer",
        ),
        (
            io::ErrorKind::TimedOut,
            "operação de rede excedeu o tempo limite",
        ),
        (
            io::ErrorKind::InvalidInput,
            "endereço ou parâmetro de rede inválido",
        ),
        (io::ErrorKind::AddrInUse, "endereço ou porta já está em uso"),
        (
            io::ErrorKind::AddrNotAvailable,
            "endereço não está disponível nesta máquina",
        ),
        (io::ErrorKind::NetworkUnreachable, "rede inacessível"),
        (io::ErrorKind::HostUnreachable, "host inacessível"),
        (io::ErrorKind::Other, "falha de rede"),
    ];

    for (tipo, esperado) in casos {
        let erro = io::Error::from(tipo);
        assert_eq!(mensagem_erro_rede(&erro), esperado);
    }
}

#[test]
fn validacao_aceita_socketaddr_numerico_sem_dns() {
    let endereco: SocketAddr = "192.168.50.10:7777".parse().unwrap();
    assert_eq!(parse_endereco_local(&endereco.to_string()), Ok(endereco));
}

#[test]
fn cli_rejeita_endereco_publico_e_hostname_com_erro_curto() {
    for endereco in ["8.8.8.8:7777", "localhost:7777"] {
        let saida = Command::new(env!("CARGO_BIN_EXE_securechat"))
            .args(["connect", endereco])
            .output()
            .expect("executar CLI");
        assert!(!saida.status.success());
        let stderr = String::from_utf8(saida.stderr).expect("stderr UTF-8");
        assert!(stderr.contains("endereço IP local ou porta inválidos"));
        assert!(!stderr.contains("private key"));
    }
}

#[test]
fn cli_classifica_connection_refused_sem_contexto_criptografico() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endereco = listener.local_addr().unwrap();
    drop(listener);

    let saida = Command::new(env!("CARGO_BIN_EXE_securechat"))
        .args(["connect", &endereco.to_string()])
        .output()
        .expect("executar CLI");
    assert!(!saida.status.success());
    let stderr = String::from_utf8(saida.stderr).expect("stderr UTF-8");
    assert!(stderr.contains("conexão recusada pelo peer"));
    assert!(!stderr.contains("Noise"));
}
