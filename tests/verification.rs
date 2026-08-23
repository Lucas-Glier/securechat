use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use securechat::framing::{escrever_frame, ler_frame};
use securechat::tcp_handshake::{SessaoEstabelecida, executar_initiator, executar_responder};
use securechat::verification::{EstadoSessao, EventoRemoto, MotivoClose, SessaoVerificacao};

fn par_tcp() -> (SessaoEstabelecida, SessaoEstabelecida) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener loopback");
    let endereco = listener.local_addr().expect("endereço local");
    let responder = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        executar_responder(stream).expect("handshake responder")
    });
    let initiator = executar_initiator(TcpStream::connect(endereco).expect("connect"))
        .expect("handshake initiator");
    (initiator, responder.join().expect("thread responder"))
}

fn trocar_frame(remetente: &mut TcpStream, destinatario: &mut TcpStream, body: &[u8]) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(2);
    escrever_frame(remetente, body, deadline).expect("escrever frame");
    ler_frame(destinatario, deadline).expect("ler frame")
}

fn par_verified_tcp() -> (TcpStream, SessaoVerificacao, TcpStream, SessaoVerificacao) {
    let (alice, bob) = par_tcp();
    let (mut stream_alice, canal_alice) = alice.into_parts();
    let (mut stream_bob, canal_bob) = bob.into_parts();
    let mut alice = SessaoVerificacao::new(canal_alice);
    let mut bob = SessaoVerificacao::new(canal_bob);

    let de_alice = alice.confirmar_localmente().expect("confirmação Alice");
    let recebido = trocar_frame(&mut stream_alice, &mut stream_bob, &de_alice);
    bob.processar_ciphertext(&recebido).expect("Bob confirma");
    let de_bob = bob.confirmar_localmente().expect("confirmação Bob");
    let recebido = trocar_frame(&mut stream_bob, &mut stream_alice, &de_bob);
    alice
        .processar_ciphertext(&recebido)
        .expect("Alice confirma");

    assert_eq!(alice.estado(), EstadoSessao::Verified);
    assert_eq!(bob.estado(), EstadoSessao::Verified);
    (stream_alice, alice, stream_bob, bob)
}

#[test]
fn confirmacao_honesta_via_tcp_leva_ambos_a_verified_sem_chat() {
    let (alice, bob) = par_tcp();
    let (mut stream_alice, canal_alice) = alice.into_parts();
    let (mut stream_bob, canal_bob) = bob.into_parts();
    let mut alice = SessaoVerificacao::new(canal_alice);
    let mut bob = SessaoVerificacao::new(canal_bob);

    let confirmacao_alice = alice.confirmar_localmente().expect("confirmação Alice");
    let recebida = trocar_frame(&mut stream_alice, &mut stream_bob, &confirmacao_alice);
    assert!(matches!(
        bob.processar_ciphertext(&recebida).expect("Bob processa"),
        EventoRemoto::VerifyConfirmed
    ));
    assert_eq!(bob.estado(), EstadoSessao::Unverified);

    let confirmacao_bob = bob.confirmar_localmente().expect("confirmação Bob");
    let recebida = trocar_frame(&mut stream_bob, &mut stream_alice, &confirmacao_bob);
    assert!(matches!(
        alice
            .processar_ciphertext(&recebida)
            .expect("Alice processa"),
        EventoRemoto::VerifyConfirmed
    ));

    assert_eq!(alice.estado(), EstadoSessao::Verified);
    assert_eq!(bob.estado(), EstadoSessao::Verified);
    // Os únicos plaintexts produzidos foram os controles de um byte.
    assert_eq!(confirmacao_alice.len(), 17);
    assert_eq!(confirmacao_bob.len(), 17);
}

#[test]
fn confirmacao_remota_via_tcp_nao_substitui_decisao_local() {
    let (alice, bob) = par_tcp();
    let (mut stream_alice, canal_alice) = alice.into_parts();
    let (mut stream_bob, canal_bob) = bob.into_parts();
    let mut alice = SessaoVerificacao::new(canal_alice);
    let mut bob = SessaoVerificacao::new(canal_bob);

    let confirmacao_bob = bob.confirmar_localmente().expect("confirmação Bob");
    let recebida = trocar_frame(&mut stream_bob, &mut stream_alice, &confirmacao_bob);
    alice
        .processar_ciphertext(&recebida)
        .expect("Alice processa");

    assert!(alice.peer_confirmed());
    assert!(!alice.local_confirmed());
    assert_eq!(alice.estado(), EstadoSessao::Unverified);
}

#[test]
fn close_autenticado_via_tcp_recebe_resposta_reciproca() {
    let (alice, bob) = par_tcp();
    let (mut stream_alice, canal_alice) = alice.into_parts();
    let (mut stream_bob, canal_bob) = bob.into_parts();
    let mut alice = SessaoVerificacao::new(canal_alice);
    let mut bob = SessaoVerificacao::new(canal_bob);

    let close = alice
        .iniciar_close(MotivoClose::VerificationAborted)
        .expect("CLOSE Alice");
    let recebido = trocar_frame(&mut stream_alice, &mut stream_bob, &close);
    let resposta = match bob.processar_ciphertext(&recebido).expect("CLOSE Bob") {
        EventoRemoto::Close { motivo, resposta } => {
            assert_eq!(motivo, MotivoClose::VerificationAborted);
            resposta.expect("resposta recíproca")
        }
        EventoRemoto::VerifyConfirmed | EventoRemoto::Chat(_) => panic!("controle inesperado"),
    };
    let recebida = trocar_frame(&mut stream_bob, &mut stream_alice, &resposta);
    assert!(matches!(
        alice
            .processar_ciphertext(&recebida)
            .expect("resposta Alice"),
        EventoRemoto::Close {
            motivo: MotivoClose::VerificationAborted,
            resposta: None
        }
    ));
    alice.concluir_close_recebido();
    bob.concluir_close_recebido();
    assert_eq!(alice.estado(), EstadoSessao::Closed);
    assert_eq!(bob.estado(), EstadoSessao::Closed);
}

#[test]
fn frame_truncado_em_unverified_e_interrupcao_nao_sao_close_autenticado() {
    let (alice, bob) = par_tcp();
    let (mut stream_alice, canal_alice) = alice.into_parts();
    let (mut stream_bob, canal_bob) = bob.into_parts();
    let _alice = SessaoVerificacao::new(canal_alice);
    let mut bob = SessaoVerificacao::new(canal_bob);

    stream_alice
        .write_all(&17_u32.to_be_bytes())
        .expect("prefixo");
    stream_alice.write_all(&[0_u8; 3]).expect("body parcial");
    stream_alice.shutdown(Shutdown::Write).expect("shutdown");

    assert!(ler_frame(&mut stream_bob, Instant::now() + Duration::from_secs(2)).is_err());
    bob.registrar_interrupcao();
    assert_eq!(bob.estado(), EstadoSessao::Closed);
}

#[test]
fn chat_tcp_bidirecional_e_multiplas_mensagens_preservam_ordem() {
    let (mut stream_alice, mut alice, mut stream_bob, mut bob) = par_verified_tcp();

    for esperada in ["alice-1", "alice-2", "alice-3"] {
        let ciphertext = alice.enviar_chat(esperada).expect("CHAT Alice");
        let recebido = trocar_frame(&mut stream_alice, &mut stream_bob, &ciphertext);
        assert!(matches!(
            bob.processar_ciphertext(&recebido).expect("CHAT em Bob"),
            EventoRemoto::Chat(conteudo) if conteudo == esperada
        ));
    }

    for esperada in ["bob-1", "bob-2"] {
        let ciphertext = bob.enviar_chat(esperada).expect("CHAT Bob");
        let recebido = trocar_frame(&mut stream_bob, &mut stream_alice, &ciphertext);
        assert!(matches!(
            alice
                .processar_ciphertext(&recebido)
                .expect("CHAT em Alice"),
            EventoRemoto::Chat(conteudo) if conteudo == esperada
        ));
    }
}

#[test]
fn close_normal_durante_conversa_e_autenticado_e_reciproco() {
    let (mut stream_alice, mut alice, mut stream_bob, mut bob) = par_verified_tcp();
    let mensagem = alice.enviar_chat("antes do encerramento").unwrap();
    let recebida = trocar_frame(&mut stream_alice, &mut stream_bob, &mensagem);
    assert!(matches!(
        bob.processar_ciphertext(&recebida).unwrap(),
        EventoRemoto::Chat(_)
    ));

    let close = alice.iniciar_close(MotivoClose::Normal).unwrap();
    let recebido = trocar_frame(&mut stream_alice, &mut stream_bob, &close);
    let resposta = match bob.processar_ciphertext(&recebido).unwrap() {
        EventoRemoto::Close {
            motivo: MotivoClose::Normal,
            resposta: Some(resposta),
        } => resposta,
        _ => panic!("CLOSE NORMAL esperado"),
    };
    let recebido = trocar_frame(&mut stream_bob, &mut stream_alice, &resposta);
    assert!(matches!(
        alice.processar_ciphertext(&recebido).unwrap(),
        EventoRemoto::Close {
            motivo: MotivoClose::Normal,
            resposta: None
        }
    ));
}

#[test]
fn close_remoto_impede_envio_de_entrada_local_pendente() {
    let (mut stream_alice, mut alice, mut stream_bob, mut bob) = par_verified_tcp();

    let close = alice.iniciar_close(MotivoClose::Normal).unwrap();
    let recebido = trocar_frame(&mut stream_alice, &mut stream_bob, &close);
    assert!(matches!(
        bob.processar_ciphertext(&recebido).unwrap(),
        EventoRemoto::Close {
            motivo: MotivoClose::Normal,
            ..
        }
    ));
    assert_eq!(bob.estado(), EstadoSessao::Closing);

    // Representa uma linha já obtida pela thread de entrada, mas ainda não
    // cifrada pelo proprietário da sessão quando o CLOSE remoto foi processado.
    assert!(bob.enviar_chat("entrada local pendente").is_err());
}

#[test]
fn eof_abrupto_em_verified_nao_e_close_autenticado() {
    let (stream_alice, _alice, _stream_bob, mut bob) = par_verified_tcp();
    stream_alice.shutdown(Shutdown::Both).expect("shutdown");
    bob.registrar_interrupcao();
    assert_eq!(bob.estado(), EstadoSessao::Closed);
}

#[test]
fn frame_truncado_em_verified_nao_produz_chat() {
    let (mut stream_alice, _alice, mut stream_bob, mut bob) = par_verified_tcp();
    stream_alice
        .write_all(&18_u32.to_be_bytes())
        .expect("prefixo");
    stream_alice.write_all(&[0_u8; 4]).expect("body parcial");
    stream_alice.shutdown(Shutdown::Write).expect("shutdown");

    assert!(ler_frame(&mut stream_bob, Instant::now() + Duration::from_secs(2)).is_err());
    bob.registrar_interrupcao();
    assert_eq!(bob.estado(), EstadoSessao::Closed);
}

#[test]
fn chat_com_sentinela_nao_cria_artefato_persistente_da_aplicacao() {
    let sufixo = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("relógio")
        .as_nanos();
    let sentinela = format!("securechat-sentinela-{}-{sufixo}", std::process::id());
    let laboratorio = std::env::temp_dir().join(format!(
        "securechat-persistencia-{}-{sufixo}",
        std::process::id()
    ));
    std::fs::create_dir(&laboratorio).expect("diretório isolado");

    let (_stream_alice, mut alice, _stream_bob, mut bob) = par_verified_tcp();
    let ciphertext = alice.enviar_chat(&sentinela).expect("CHAT sentinela");
    assert!(matches!(
        bob.processar_ciphertext(&ciphertext).expect("receber sentinela"),
        EventoRemoto::Chat(conteudo) if conteudo == sentinela
    ));

    // O aplicativo não possui história, arquivo ou logger de mensagens. Este
    // teste observa somente o diretório isolado destinado a artefatos do teste;
    // não faz alegação sobre terminal, memória, SO ou eliminação forense.
    assert_eq!(
        std::fs::read_dir(&laboratorio)
            .expect("inspecionar laboratório")
            .count(),
        0
    );
    std::fs::remove_dir(&laboratorio).expect("remover laboratório vazio");
}
