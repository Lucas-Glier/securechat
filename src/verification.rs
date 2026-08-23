use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use crate::DynError;
use crate::framing::{escrever_frame, ler_frame_sessao};
use crate::noise_lab::CanalNoise;
use crate::tcp_handshake::SessaoEstabelecida;
use zeroize::Zeroize;

const VERIFY_CONFIRMED: u8 = 0x01;
const CHAT: u8 = 0x02;
const CLOSE: u8 = 0x03;
const TRANSPORT_BUFFER_SIZE: usize = 8192;
pub const MAX_CHAT_CONTENT: usize = 4096;
pub const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const CLOSE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
pub const VERIFIED_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

struct ControleIdle {
    duracao: Duration,
    deadline: Instant,
}

impl ControleIdle {
    fn new(duracao: Duration, agora: Instant) -> Self {
        Self {
            duracao,
            deadline: agora + duracao,
        }
    }

    fn registrar_atividade(&mut self, agora: Instant) {
        self.deadline = agora + self.duracao;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EstadoSessao {
    Unverified,
    Verified,
    Closing,
    Closed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MotivoClose {
    Normal = 0x00,
    VerificationAborted = 0x01,
    IdleTimeout = 0x02,
}

impl MotivoClose {
    fn from_byte(valor: u8) -> Option<Self> {
        match valor {
            0x00 => Some(Self::Normal),
            0x01 => Some(Self::VerificationAborted),
            0x02 => Some(Self::IdleTimeout),
            _ => None,
        }
    }
}

pub enum EventoRemoto {
    VerifyConfirmed,
    Chat(String),
    Close {
        motivo: MotivoClose,
        resposta: Option<Vec<u8>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CategoriaErroSessao {
    Aead,
    Protocolo,
    Estado,
}

pub struct ErroSessao {
    categoria: CategoriaErroSessao,
    mensagem: &'static str,
}

impl ErroSessao {
    fn novo(categoria: CategoriaErroSessao, mensagem: &'static str) -> Self {
        Self {
            categoria,
            mensagem,
        }
    }

    pub fn categoria(&self) -> CategoriaErroSessao {
        self.categoria
    }
}

impl fmt::Display for ErroSessao {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.mensagem)
    }
}

impl fmt::Debug for ErroSessao {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErroSessao")
            .field("categoria", &self.categoria)
            .field("mensagem", &self.mensagem)
            .finish()
    }
}

impl Error for ErroSessao {}

pub struct SessaoVerificacao {
    canal: CanalNoise,
    estado: EstadoSessao,
    local_confirmed: bool,
    peer_confirmed: bool,
    verify_sent: bool,
    close_sent: bool,
    peer_close_received: bool,
}

impl SessaoVerificacao {
    pub fn new(canal: CanalNoise) -> Self {
        Self {
            canal,
            estado: EstadoSessao::Unverified,
            local_confirmed: false,
            peer_confirmed: false,
            verify_sent: false,
            close_sent: false,
            peer_close_received: false,
        }
    }

    pub fn estado(&self) -> EstadoSessao {
        self.estado
    }

    pub fn local_confirmed(&self) -> bool {
        self.local_confirmed
    }

    pub fn peer_confirmed(&self) -> bool {
        self.peer_confirmed
    }

    pub fn fingerprint(&self) -> &str {
        self.canal.fingerprint()
    }

    pub fn confirmar_localmente(&mut self) -> Result<Vec<u8>, ErroSessao> {
        self.exigir_estado(EstadoSessao::Unverified)?;
        if self.local_confirmed || self.verify_sent {
            return self.falhar_protocolo("confirmação local duplicada");
        }

        let ciphertext = self.cifrar(&[VERIFY_CONFIRMED])?;
        self.local_confirmed = true;
        self.verify_sent = true;
        self.atualizar_verified();
        Ok(ciphertext)
    }

    pub fn enviar_chat(&mut self, conteudo: &str) -> Result<Vec<u8>, ErroSessao> {
        self.exigir_estado(EstadoSessao::Verified)?;
        let tamanho = conteudo.len();
        if tamanho == 0 {
            return Err(ErroSessao::novo(
                CategoriaErroSessao::Protocolo,
                "CHAT vazio",
            ));
        }
        if tamanho > MAX_CHAT_CONTENT {
            return Err(ErroSessao::novo(
                CategoriaErroSessao::Protocolo,
                "CHAT excede 4096 bytes",
            ));
        }

        let mut plaintext = Vec::with_capacity(tamanho + 1);
        plaintext.push(CHAT);
        plaintext.extend_from_slice(conteudo.as_bytes());
        let resultado = self.cifrar(&plaintext);
        plaintext.zeroize();
        resultado
    }

    pub fn processar_ciphertext(&mut self, ciphertext: &[u8]) -> Result<EventoRemoto, ErroSessao> {
        if matches!(self.estado, EstadoSessao::Closed | EstadoSessao::Failed) {
            return Err(ErroSessao::novo(
                CategoriaErroSessao::Estado,
                "sessão já está em estado terminal",
            ));
        }

        let mut plaintext = [0_u8; TRANSPORT_BUFFER_SIZE];
        let tamanho = match self
            .canal
            .transport_mut()
            .read_message(ciphertext, &mut plaintext)
        {
            Ok(tamanho) => tamanho,
            Err(_) => {
                self.estado = EstadoSessao::Failed;
                return Err(ErroSessao::novo(
                    CategoriaErroSessao::Aead,
                    "falha de autenticação Noise",
                ));
            }
        };

        let resultado = match &plaintext[..tamanho] {
            [VERIFY_CONFIRMED] => self.receber_verify_confirmed(),
            [CLOSE, motivo] => self.receber_close(*motivo),
            [CHAT, conteudo @ ..] => self.receber_chat(conteudo),
            _ => self.falhar_protocolo("mensagem de aplicação inválida ou desconhecida"),
        };
        plaintext[..tamanho].zeroize();
        resultado
    }

    pub fn iniciar_close(&mut self, motivo: MotivoClose) -> Result<Vec<u8>, ErroSessao> {
        if !matches!(
            self.estado,
            EstadoSessao::Unverified | EstadoSessao::Verified
        ) {
            return Err(ErroSessao::novo(
                CategoriaErroSessao::Estado,
                "CLOSE local inválido no estado atual",
            ));
        }
        if self.close_sent {
            return self.falhar_protocolo("CLOSE local duplicado");
        }

        let ciphertext = self.cifrar(&[CLOSE, motivo as u8])?;
        self.close_sent = true;
        self.estado = EstadoSessao::Closing;
        Ok(ciphertext)
    }

    pub fn divergencia_local(&mut self) -> Result<Vec<u8>, ErroSessao> {
        self.exigir_estado(EstadoSessao::Unverified)?;
        let ciphertext = self.cifrar(&[CLOSE, MotivoClose::VerificationAborted as u8])?;
        self.close_sent = true;
        self.estado = EstadoSessao::Failed;
        Ok(ciphertext)
    }

    pub fn cancelamento_local(&mut self) -> Result<Vec<u8>, ErroSessao> {
        self.exigir_estado(EstadoSessao::Unverified)?;
        let ciphertext = self.cifrar(&[CLOSE, MotivoClose::VerificationAborted as u8])?;
        self.close_sent = true;
        self.estado = EstadoSessao::Closed;
        Ok(ciphertext)
    }

    pub fn timeout_verificacao(&mut self) -> Result<Vec<u8>, ErroSessao> {
        self.exigir_estado(EstadoSessao::Unverified)?;
        let ciphertext = self.cifrar(&[CLOSE, MotivoClose::VerificationAborted as u8])?;
        self.close_sent = true;
        self.estado = EstadoSessao::Closed;
        Ok(ciphertext)
    }

    pub fn timeout_idle(&mut self) -> Result<Vec<u8>, ErroSessao> {
        self.exigir_estado(EstadoSessao::Verified)?;
        self.iniciar_close(MotivoClose::IdleTimeout)
    }

    pub fn concluir_close_recebido(&mut self) {
        if self.peer_close_received {
            self.estado = EstadoSessao::Closed;
        }
    }

    pub fn timeout_close(&mut self) {
        if self.estado == EstadoSessao::Closing {
            self.estado = EstadoSessao::Closed;
        }
    }

    pub fn registrar_interrupcao(&mut self) {
        if !matches!(self.estado, EstadoSessao::Closed | EstadoSessao::Failed) {
            self.estado = EstadoSessao::Closed;
        }
    }

    pub fn registrar_falha_protocolo(&mut self) {
        if !matches!(self.estado, EstadoSessao::Closed | EstadoSessao::Failed) {
            self.estado = EstadoSessao::Failed;
        }
    }

    fn receber_verify_confirmed(&mut self) -> Result<EventoRemoto, ErroSessao> {
        if self.estado != EstadoSessao::Unverified {
            return self.falhar_protocolo("VERIFY_CONFIRMED fora de UNVERIFIED");
        }
        if self.peer_confirmed {
            return self.falhar_protocolo("VERIFY_CONFIRMED remoto duplicado");
        }
        self.peer_confirmed = true;
        self.atualizar_verified();
        Ok(EventoRemoto::VerifyConfirmed)
    }

    fn receber_chat(&mut self, conteudo: &[u8]) -> Result<EventoRemoto, ErroSessao> {
        self.exigir_estado(EstadoSessao::Verified)
            .or_else(|_| self.falhar_protocolo("CHAT fora de VERIFIED"))?;
        if conteudo.is_empty() {
            return self.falhar_protocolo("CHAT vazio");
        }
        if conteudo.len() > MAX_CHAT_CONTENT {
            return self.falhar_protocolo("CHAT excede 4096 bytes");
        }
        let conteudo = match std::str::from_utf8(conteudo) {
            Ok(conteudo) => conteudo.to_owned(),
            Err(_) => return self.falhar_protocolo("CHAT contém UTF-8 inválido"),
        };
        Ok(EventoRemoto::Chat(conteudo))
    }

    fn receber_close(&mut self, valor: u8) -> Result<EventoRemoto, ErroSessao> {
        if !matches!(
            self.estado,
            EstadoSessao::Unverified | EstadoSessao::Verified | EstadoSessao::Closing
        ) {
            return self.falhar_protocolo("CLOSE inválido no estado atual");
        }
        if self.peer_close_received {
            return self.falhar_protocolo("CLOSE remoto duplicado");
        }
        let motivo = match MotivoClose::from_byte(valor) {
            Some(motivo) => motivo,
            None => return self.falhar_protocolo("reason de CLOSE desconhecido"),
        };

        self.peer_close_received = true;
        let resposta = if self.close_sent {
            None
        } else {
            let resposta = self.cifrar(&[CLOSE, motivo as u8])?;
            self.close_sent = true;
            Some(resposta)
        };
        self.estado = EstadoSessao::Closing;
        Ok(EventoRemoto::Close { motivo, resposta })
    }

    fn cifrar(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ErroSessao> {
        let mut ciphertext = [0_u8; TRANSPORT_BUFFER_SIZE];
        let tamanho = self
            .canal
            .transport_mut()
            .write_message(plaintext, &mut ciphertext)
            .map_err(|_| {
                self.estado = EstadoSessao::Failed;
                ErroSessao::novo(CategoriaErroSessao::Aead, "falha de cifra Noise")
            })?;
        Ok(ciphertext[..tamanho].to_vec())
    }

    fn atualizar_verified(&mut self) {
        if self.estado == EstadoSessao::Unverified && self.local_confirmed && self.peer_confirmed {
            self.estado = EstadoSessao::Verified;
        }
    }

    fn exigir_estado(&self, esperado: EstadoSessao) -> Result<(), ErroSessao> {
        if self.estado != esperado {
            return Err(ErroSessao::novo(
                CategoriaErroSessao::Estado,
                "evento inválido no estado atual",
            ));
        }
        Ok(())
    }

    fn falhar_protocolo<T>(&mut self, mensagem: &'static str) -> Result<T, ErroSessao> {
        self.estado = EstadoSessao::Failed;
        Err(ErroSessao::novo(CategoriaErroSessao::Protocolo, mensagem))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultadoInterativo {
    VerifiedAndClosed,
    AuthenticatedClose,
    LocalCancellation,
    FingerprintMismatch,
    VerificationTimeout,
    CloseTimeout,
    NetworkInterruption,
    ProtocolFailure,
    AeadFailure,
}

#[derive(Clone, Copy)]
enum DecisaoUsuario {
    Confirma,
    Diverge,
    Cancela,
}

enum EventoRuntime {
    Verificacao(DecisaoUsuario),
    LinhaChat(LinhaPendente),
    EncerrarLocalmente,
    Rede(Result<Vec<u8>, io::Error>),
}

struct LinhaPendente(String);

impl LinhaPendente {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for LinhaPendente {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn executar_verificacao_interativa(
    sessao: SessaoEstabelecida,
) -> Result<ResultadoInterativo, DynError> {
    executar_sessao_interativa_com_timeouts(sessao, VERIFICATION_TIMEOUT, VERIFIED_IDLE_TIMEOUT)
}

fn executar_sessao_interativa_com_timeouts(
    sessao: SessaoEstabelecida,
    timeout_verificacao: Duration,
    timeout_idle: Duration,
) -> Result<ResultadoInterativo, DynError> {
    let (mut stream, canal) = sessao.into_parts();
    let mut verificacao = SessaoVerificacao::new(canal);
    let deadline_verificacao = Instant::now() + timeout_verificacao;
    // O limite evita acúmulo ilimitado de linhas plaintext ou frames pendentes.
    let (tx, rx) = mpsc::sync_channel(1);

    println!("Estado: UNVERIFIED");
    println!("\nFingerprint:\n{}", verificacao.fingerprint());
    println!("\nCompare o valor completo com a outra pessoa por um canal independente.");
    println!("\n[s] corresponde integralmente\n[n] não corresponde\n[c] cancelar");
    print!("Escolha: ");
    io::stdout().flush()?;

    iniciar_leitura_verificacao(tx.clone());
    iniciar_leitura_rede(stream.try_clone()?, tx.clone());

    let mut close_deadline = None;
    let mut controle_idle = None;
    let mut entrada_chat_iniciada = false;
    let mut chegou_a_verified = false;

    loop {
        if verificacao.estado() == EstadoSessao::Verified && !entrada_chat_iniciada {
            chegou_a_verified = true;
            entrada_chat_iniciada = true;
            controle_idle = Some(ControleIdle::new(timeout_idle, Instant::now()));
            println!("\nEstado: VERIFIED");
            println!("Verificação mútua coordenada.");
            println!("Digite mensagens ou /sair para encerrar.");
            iniciar_leitura_chat(tx.clone());
        }

        let deadline_atual = match verificacao.estado() {
            EstadoSessao::Unverified => deadline_verificacao,
            EstadoSessao::Verified => {
                controle_idle
                    .as_ref()
                    .expect("VERIFIED possui idle deadline")
                    .deadline
            }
            EstadoSessao::Closing => close_deadline.expect("CLOSING possui close deadline"),
            EstadoSessao::Closed | EstadoSessao::Failed => {
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(ResultadoInterativo::ProtocolFailure);
            }
        };
        let espera = match deadline_atual.checked_duration_since(Instant::now()) {
            Some(espera) if !espera.is_zero() => espera,
            _ => {
                if let Some(resultado) =
                    tratar_timeout(&mut verificacao, &mut stream, &mut close_deadline)?
                {
                    return Ok(resultado);
                }
                continue;
            }
        };

        let evento = match rx.recv_timeout(espera) {
            Ok(evento) => evento,
            Err(RecvTimeoutError::Timeout) => {
                if let Some(resultado) =
                    tratar_timeout(&mut verificacao, &mut stream, &mut close_deadline)?
                {
                    return Ok(resultado);
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
                verificacao.registrar_interrupcao();
                return Ok(ResultadoInterativo::NetworkInterruption);
            }
        };

        match evento {
            EventoRuntime::Verificacao(decisao) => {
                if verificacao.estado() != EstadoSessao::Unverified {
                    continue;
                }
                match decisao {
                    DecisaoUsuario::Confirma => {
                        let ciphertext = verificacao.confirmar_localmente()?;
                        escrever_frame(&mut stream, &ciphertext, deadline_verificacao)?;
                        if verificacao.estado() == EstadoSessao::Unverified {
                            println!("\nConfirmação local registrada e enviada.");
                            println!("Estado: UNVERIFIED");
                            println!("Aguardando a confirmação do peer.");
                        }
                    }
                    DecisaoUsuario::Diverge => {
                        let close = verificacao.divergencia_local()?;
                        let _ = escrever_frame(&mut stream, &close, deadline_verificacao);
                        println!("\nFalha de verificação: os fingerprints não correspondem.");
                        println!("A sessão não foi autenticada.");
                        let _ = stream.shutdown(Shutdown::Both);
                        return Ok(ResultadoInterativo::FingerprintMismatch);
                    }
                    DecisaoUsuario::Cancela => {
                        let close = verificacao.cancelamento_local()?;
                        let _ = escrever_frame(&mut stream, &close, deadline_verificacao);
                        println!("\nVerificação cancelada.");
                        println!("A sessão permanece não autenticada e será encerrada.");
                        let _ = stream.shutdown(Shutdown::Both);
                        return Ok(ResultadoInterativo::LocalCancellation);
                    }
                }
            }
            EventoRuntime::LinhaChat(conteudo) => {
                if verificacao.estado() != EstadoSessao::Verified {
                    continue;
                }
                match verificacao.enviar_chat(conteudo.as_str()) {
                    Ok(ciphertext) => {
                        let resultado = escrever_frame(
                            &mut stream,
                            &ciphertext,
                            Instant::now() + crate::framing::FRAME_PROGRESS_TIMEOUT,
                        );
                        if resultado.is_err() {
                            verificacao.registrar_interrupcao();
                            let _ = stream.shutdown(Shutdown::Both);
                            return Ok(ResultadoInterativo::NetworkInterruption);
                        }
                        println!("Você: {}", conteudo.as_str());
                        controle_idle
                            .as_mut()
                            .expect("VERIFIED possui controle idle")
                            .registrar_atividade(Instant::now());
                    }
                    Err(erro) => {
                        if erro.categoria() == CategoriaErroSessao::Estado {
                            continue;
                        }
                        println!("Mensagem rejeitada: use entre 1 e 4096 bytes UTF-8.");
                    }
                }
            }
            EventoRuntime::EncerrarLocalmente => match verificacao.estado() {
                EstadoSessao::Unverified => {
                    let close = verificacao.cancelamento_local()?;
                    let _ = escrever_frame(
                        &mut stream,
                        &close,
                        Instant::now() + CLOSE_RESPONSE_TIMEOUT,
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                    return Ok(ResultadoInterativo::LocalCancellation);
                }
                EstadoSessao::Verified => {
                    let close = verificacao.iniciar_close(MotivoClose::Normal)?;
                    let deadline = Instant::now() + CLOSE_RESPONSE_TIMEOUT;
                    if escrever_frame(&mut stream, &close, deadline).is_err() {
                        verificacao.registrar_interrupcao();
                        let _ = stream.shutdown(Shutdown::Both);
                        return Ok(ResultadoInterativo::NetworkInterruption);
                    }
                    close_deadline = Some(deadline);
                }
                EstadoSessao::Closing | EstadoSessao::Closed | EstadoSessao::Failed => {}
            },
            EventoRuntime::Rede(Ok(ciphertext)) => {
                let evento = match verificacao.processar_ciphertext(&ciphertext) {
                    Ok(evento) => evento,
                    Err(erro) => {
                        let _ = stream.shutdown(Shutdown::Both);
                        return Ok(match erro.categoria() {
                            CategoriaErroSessao::Aead => ResultadoInterativo::AeadFailure,
                            CategoriaErroSessao::Protocolo | CategoriaErroSessao::Estado => {
                                ResultadoInterativo::ProtocolFailure
                            }
                        });
                    }
                };

                match evento {
                    EventoRemoto::VerifyConfirmed => {
                        if verificacao.estado() == EstadoSessao::Unverified {
                            println!("\nConfirmação remota autenticada recebida.");
                            println!("Estado: UNVERIFIED");
                            println!("A confirmação local ainda é obrigatória.");
                        }
                    }
                    EventoRemoto::Chat(mut conteudo) => {
                        println!("Peer: {conteudo}");
                        conteudo.zeroize();
                        controle_idle
                            .as_mut()
                            .expect("VERIFIED possui controle idle")
                            .registrar_atividade(Instant::now());
                    }
                    EventoRemoto::Close { motivo, resposta } => {
                        if let Some(resposta) = resposta {
                            let deadline = Instant::now() + CLOSE_RESPONSE_TIMEOUT;
                            // O peer pode fechar imediatamente após um CLOSE de aborto. A
                            // especificação manda encerrar depois da resposta ser escrita ou
                            // ocorrer erro de escrita; o CLOSE recebido continua autenticado.
                            let _ = escrever_frame(&mut stream, &resposta, deadline);
                        }
                        verificacao.concluir_close_recebido();
                        println!("\nCLOSE autenticado recebido: {}.", nome_motivo(motivo));
                        let _ = stream.shutdown(Shutdown::Both);
                        return Ok(if chegou_a_verified {
                            ResultadoInterativo::VerifiedAndClosed
                        } else {
                            ResultadoInterativo::AuthenticatedClose
                        });
                    }
                }
            }
            EventoRuntime::Rede(Err(erro)) => {
                if erro.kind() == io::ErrorKind::InvalidData {
                    verificacao.registrar_falha_protocolo();
                    let _ = stream.shutdown(Shutdown::Both);
                    return Ok(ResultadoInterativo::ProtocolFailure);
                }
                verificacao.registrar_interrupcao();
                println!("\nConexão encerrada sem CLOSE autenticado.");
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(ResultadoInterativo::NetworkInterruption);
            }
        }
    }
}

fn iniciar_leitura_verificacao(tx: SyncSender<EventoRuntime>) {
    thread::spawn(move || {
        loop {
            let mut entrada = String::new();
            let decisao = match io::stdin().read_line(&mut entrada) {
                Ok(0) => DecisaoUsuario::Cancela,
                Ok(_) => match entrada.trim().to_ascii_lowercase().as_str() {
                    "s" => DecisaoUsuario::Confirma,
                    "n" => DecisaoUsuario::Diverge,
                    "c" => DecisaoUsuario::Cancela,
                    _ => {
                        print!("Escolha inválida. Use s, n ou c: ");
                        let _ = io::stdout().flush();
                        continue;
                    }
                },
                Err(_) => DecisaoUsuario::Cancela,
            };
            let _ = tx.send(EventoRuntime::Verificacao(decisao));
            break;
        }
    });
}

fn iniciar_leitura_chat(tx: SyncSender<EventoRuntime>) {
    thread::spawn(move || {
        loop {
            let mut entrada = String::new();
            match io::stdin().read_line(&mut entrada) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(EventoRuntime::EncerrarLocalmente);
                    break;
                }
                Ok(_) => {
                    remover_terminador_linha(&mut entrada);
                    if entrada == "/sair" {
                        entrada.zeroize();
                        let _ = tx.send(EventoRuntime::EncerrarLocalmente);
                        break;
                    }
                    if tx
                        .send(EventoRuntime::LinhaChat(LinhaPendente(entrada)))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
}

fn remover_terminador_linha(entrada: &mut String) {
    if entrada.ends_with('\n') {
        entrada.pop();
        if entrada.ends_with('\r') {
            entrada.pop();
        }
    }
}

fn iniciar_leitura_rede(mut stream: TcpStream, tx: SyncSender<EventoRuntime>) {
    thread::spawn(move || {
        loop {
            let resultado = ler_frame_sessao(&mut stream);
            let terminal = resultado.is_err();
            if tx.send(EventoRuntime::Rede(resultado)).is_err() || terminal {
                break;
            }
        }
    });
}

fn tratar_timeout(
    verificacao: &mut SessaoVerificacao,
    stream: &mut TcpStream,
    close_deadline: &mut Option<Instant>,
) -> Result<Option<ResultadoInterativo>, DynError> {
    match verificacao.estado() {
        EstadoSessao::Closing => {
            verificacao.timeout_close();
            println!(
                "\nTimeout aguardando resposta a CLOSE; encerramento não confirmado pelo peer."
            );
            let _ = stream.shutdown(Shutdown::Both);
            Ok(Some(ResultadoInterativo::CloseTimeout))
        }
        EstadoSessao::Unverified => {
            let close = verificacao.timeout_verificacao()?;
            let deadline = Instant::now() + CLOSE_RESPONSE_TIMEOUT;
            let _ = escrever_frame(stream, &close, deadline);
            println!("\nTimeout de verificação; a sessão não foi autenticada.");
            let _ = stream.shutdown(Shutdown::Both);
            Ok(Some(ResultadoInterativo::VerificationTimeout))
        }
        EstadoSessao::Verified => {
            let close = verificacao.timeout_idle()?;
            let deadline = Instant::now() + CLOSE_RESPONSE_TIMEOUT;
            if escrever_frame(stream, &close, deadline).is_err() {
                verificacao.registrar_interrupcao();
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(Some(ResultadoInterativo::NetworkInterruption));
            }
            println!("\nIdle timeout; CLOSE(IDLE_TIMEOUT) enviado.");
            *close_deadline = Some(deadline);
            Ok(None)
        }
        EstadoSessao::Closed | EstadoSessao::Failed => {
            Ok(Some(ResultadoInterativo::ProtocolFailure))
        }
    }
}

fn nome_motivo(motivo: MotivoClose) -> &'static str {
    match motivo {
        MotivoClose::Normal => "NORMAL",
        MotivoClose::VerificationAborted => "VERIFICATION_ABORTED",
        MotivoClose::IdleTimeout => "IDLE_TIMEOUT",
    }
}

#[cfg(test)]
mod tests {
    use crate::noise_lab::{
        HANDSHAKE_BUFFER_SIZE, criar_initiator, criar_responder, finalizar_handshake,
    };

    use super::*;

    fn par_sessoes() -> (SessaoVerificacao, SessaoVerificacao) {
        let mut alice = criar_initiator().unwrap();
        let mut bob = criar_responder().unwrap();
        let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
        let mut payload = [0_u8; HANDSHAKE_BUFFER_SIZE];

        let n = alice.write_message(&[], &mut mensagem).unwrap();
        assert_eq!(bob.read_message(&mensagem[..n], &mut payload), Ok(0));
        let n = bob.write_message(&[], &mut mensagem).unwrap();
        assert_eq!(alice.read_message(&mensagem[..n], &mut payload), Ok(0));
        let n = alice.write_message(&[], &mut mensagem).unwrap();
        assert_eq!(bob.read_message(&mensagem[..n], &mut payload), Ok(0));

        (
            SessaoVerificacao::new(finalizar_handshake(alice, [0; 3]).unwrap()),
            SessaoVerificacao::new(finalizar_handshake(bob, [0; 3]).unwrap()),
        )
    }

    fn par_verified() -> (SessaoVerificacao, SessaoVerificacao) {
        let (mut alice, mut bob) = par_sessoes();
        let de_alice = alice.confirmar_localmente().unwrap();
        let de_bob = bob.confirmar_localmente().unwrap();
        alice.processar_ciphertext(&de_bob).unwrap();
        bob.processar_ciphertext(&de_alice).unwrap();
        (alice, bob)
    }

    fn cifrar_bruto(sessao: &mut SessaoVerificacao, plaintext: &[u8]) -> Vec<u8> {
        sessao.cifrar(plaintext).unwrap()
    }

    fn categoria_erro(resultado: Result<EventoRemoto, ErroSessao>) -> CategoriaErroSessao {
        match resultado {
            Err(erro) => erro.categoria(),
            Ok(_) => panic!("a operação deveria falhar"),
        }
    }

    #[test]
    fn confirmacao_local_isolada_permanece_unverified() {
        let (mut alice, _) = par_sessoes();
        assert_eq!(alice.confirmar_localmente().unwrap().len(), 17);
        assert!(alice.local_confirmed());
        assert!(!alice.peer_confirmed());
        assert_eq!(alice.estado(), EstadoSessao::Unverified);
    }

    #[test]
    fn confirmacao_remota_isolada_nao_altera_confirmacao_local() {
        let (mut alice, mut bob) = par_sessoes();
        let ciphertext = bob.confirmar_localmente().unwrap();
        assert!(matches!(
            alice.processar_ciphertext(&ciphertext).unwrap(),
            EventoRemoto::VerifyConfirmed
        ));
        assert!(!alice.local_confirmed());
        assert!(alice.peer_confirmed());
        assert_eq!(alice.estado(), EstadoSessao::Unverified);
    }

    #[test]
    fn confirmacao_remota_antes_da_local_chega_a_verified_somente_depois() {
        let (mut alice, mut bob) = par_sessoes();
        let ciphertext = bob.confirmar_localmente().unwrap();
        alice.processar_ciphertext(&ciphertext).unwrap();
        assert_eq!(alice.estado(), EstadoSessao::Unverified);
        alice.confirmar_localmente().unwrap();
        assert_eq!(alice.estado(), EstadoSessao::Verified);
    }

    #[test]
    fn ambas_as_confirmacoes_levam_a_verified() {
        let (mut alice, mut bob) = par_sessoes();
        let de_alice = alice.confirmar_localmente().unwrap();
        let de_bob = bob.confirmar_localmente().unwrap();
        alice.processar_ciphertext(&de_bob).unwrap();
        bob.processar_ciphertext(&de_alice).unwrap();
        assert_eq!(alice.estado(), EstadoSessao::Verified);
        assert_eq!(bob.estado(), EstadoSessao::Verified);
    }

    #[test]
    fn divergencia_e_cancelamento_sao_terminais_distintos() {
        let (mut alice, mut bob) = par_sessoes();
        alice.divergencia_local().unwrap();
        bob.cancelamento_local().unwrap();
        assert_eq!(alice.estado(), EstadoSessao::Failed);
        assert_eq!(bob.estado(), EstadoSessao::Closed);
        assert!(alice.confirmar_localmente().is_err());
        assert!(bob.confirmar_localmente().is_err());
    }

    #[test]
    fn verify_confirmed_deve_ser_exatamente_um_byte() {
        let (mut alice, mut bob) = par_sessoes();
        let extra = cifrar_bruto(&mut bob, &[VERIFY_CONFIRMED, 0]);
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&extra)),
            CategoriaErroSessao::Protocolo
        );
    }

    #[test]
    fn mensagem_desconhecida_autenticada_e_chat_falham() {
        let (mut alice, mut bob) = par_sessoes();
        let desconhecida = cifrar_bruto(&mut bob, &[0x7f]);
        assert!(alice.processar_ciphertext(&desconhecida).is_err());

        let (mut alice, mut bob) = par_sessoes();
        let chat = cifrar_bruto(&mut bob, &[CHAT, b'x']);
        assert!(alice.processar_ciphertext(&chat).is_err());
    }

    #[test]
    fn confirmacao_duplicada_nova_e_replay_falham() {
        let (mut alice, mut bob) = par_sessoes();
        let primeira = cifrar_bruto(&mut bob, &[VERIFY_CONFIRMED]);
        alice.processar_ciphertext(&primeira).unwrap();
        let segunda = cifrar_bruto(&mut bob, &[VERIFY_CONFIRMED]);
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&segunda)),
            CategoriaErroSessao::Protocolo
        );

        let (mut alice, mut bob) = par_sessoes();
        let ciphertext = cifrar_bruto(&mut bob, &[VERIFY_CONFIRMED]);
        alice.processar_ciphertext(&ciphertext).unwrap();
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&ciphertext)),
            CategoriaErroSessao::Aead
        );

        let (mut alice, mut bob) = par_verified();
        let fora_de_estado = cifrar_bruto(&mut bob, &[VERIFY_CONFIRMED]);
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&fora_de_estado)),
            CategoriaErroSessao::Protocolo
        );
        assert_eq!(alice.estado(), EstadoSessao::Failed);
    }

    #[test]
    fn adulteracao_reflexao_reordenacao_e_replay_entre_sessoes_falham() {
        let (mut alice, mut bob) = par_sessoes();
        let mut adulterado = bob.confirmar_localmente().unwrap();
        let ultimo = adulterado.len() - 1;
        adulterado[ultimo] ^= 1;
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&adulterado)),
            CategoriaErroSessao::Aead
        );

        let (mut alice, _) = par_sessoes();
        let refletido = alice.confirmar_localmente().unwrap();
        assert!(alice.processar_ciphertext(&refletido).is_err());

        let (mut alice, mut bob) = par_sessoes();
        let _primeiro = cifrar_bruto(&mut bob, &[0x70]);
        let segundo = cifrar_bruto(&mut bob, &[0x71]);
        assert!(alice.processar_ciphertext(&segundo).is_err());

        let (_, mut bob_antigo) = par_sessoes();
        let antigo = cifrar_bruto(&mut bob_antigo, &[VERIFY_CONFIRMED]);
        let (mut alice_nova, _) = par_sessoes();
        assert!(alice_nova.processar_ciphertext(&antigo).is_err());
    }

    #[test]
    fn close_autenticado_verification_aborted_e_resposta_reciproca() {
        let (mut alice, mut bob) = par_sessoes();
        let close = alice
            .iniciar_close(MotivoClose::VerificationAborted)
            .unwrap();
        let evento = bob.processar_ciphertext(&close).unwrap();
        let resposta = match evento {
            EventoRemoto::Close { motivo, resposta } => {
                assert_eq!(motivo, MotivoClose::VerificationAborted);
                resposta.expect("resposta recíproca")
            }
            _ => panic!("evento inesperado"),
        };
        assert!(matches!(
            alice.processar_ciphertext(&resposta).unwrap(),
            EventoRemoto::Close { .. }
        ));
        alice.concluir_close_recebido();
        bob.concluir_close_recebido();
        assert_eq!(alice.estado(), EstadoSessao::Closed);
        assert_eq!(bob.estado(), EstadoSessao::Closed);
    }

    #[test]
    fn close_adulterado_reason_invalido_e_timeout_sao_tratados() {
        let (mut alice, mut bob) = par_sessoes();
        let mut close = bob.iniciar_close(MotivoClose::VerificationAborted).unwrap();
        let ultimo = close.len() - 1;
        close[ultimo] ^= 1;
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&close)),
            CategoriaErroSessao::Aead
        );

        let (mut alice, mut bob) = par_sessoes();
        let invalido = cifrar_bruto(&mut bob, &[CLOSE, 0xff]);
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&invalido)),
            CategoriaErroSessao::Protocolo
        );

        let (mut alice, _) = par_sessoes();
        alice.iniciar_close(MotivoClose::Normal).unwrap();
        alice.timeout_close();
        assert_eq!(alice.estado(), EstadoSessao::Closed);
    }

    #[test]
    fn timeout_e_interrupcao_nao_sao_close_autenticado() {
        let (mut alice, mut bob) = par_sessoes();
        alice.timeout_verificacao().unwrap();
        bob.registrar_interrupcao();
        assert_eq!(alice.estado(), EstadoSessao::Closed);
        assert_eq!(bob.estado(), EstadoSessao::Closed);
        assert!(!bob.peer_close_received);
    }

    #[test]
    fn chat_aceita_um_e_4096_bytes_com_ciphertext_esperado() {
        let (mut alice, mut bob) = par_verified();
        let minimo = alice.enviar_chat("x").unwrap();
        assert_eq!(minimo.len(), 18);
        assert!(matches!(
            bob.processar_ciphertext(&minimo).unwrap(),
            EventoRemoto::Chat(conteudo) if conteudo == "x"
        ));

        let maximo = "a".repeat(MAX_CHAT_CONTENT);
        let ciphertext = alice.enviar_chat(&maximo).unwrap();
        assert_eq!(ciphertext.len(), 4113);
        assert!(matches!(
            bob.processar_ciphertext(&ciphertext).unwrap(),
            EventoRemoto::Chat(conteudo) if conteudo.len() == MAX_CHAT_CONTENT
        ));
    }

    #[test]
    fn chat_local_vazio_e_4097_sao_rejeitados_sem_consumir_nonce() {
        let (mut alice, mut bob) = par_verified();
        assert!(alice.enviar_chat("").is_err());
        assert!(
            alice
                .enviar_chat(&"a".repeat(MAX_CHAT_CONTENT + 1))
                .is_err()
        );

        let valido = alice.enviar_chat("válido").unwrap();
        assert!(matches!(
            bob.processar_ciphertext(&valido).unwrap(),
            EventoRemoto::Chat(conteudo) if conteudo == "válido"
        ));
    }

    #[test]
    fn chat_remoto_vazio_grande_e_utf8_invalido_falham() {
        let (mut alice, mut bob) = par_verified();
        let vazio = cifrar_bruto(&mut bob, &[CHAT]);
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&vazio)),
            CategoriaErroSessao::Protocolo
        );

        let (mut alice, mut bob) = par_verified();
        let mut grande = vec![CHAT];
        grande.extend(std::iter::repeat_n(b'a', MAX_CHAT_CONTENT + 1));
        let grande = cifrar_bruto(&mut bob, &grande);
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&grande)),
            CategoriaErroSessao::Protocolo
        );

        let (mut alice, mut bob) = par_verified();
        let invalido = cifrar_bruto(&mut bob, &[CHAT, 0xff]);
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&invalido)),
            CategoriaErroSessao::Protocolo
        );
    }

    #[test]
    fn chat_antes_de_verified_e_depois_de_closing_falha() {
        let (mut alice, mut bob) = par_sessoes();
        assert_eq!(
            alice.enviar_chat("não permitido").unwrap_err().categoria(),
            CategoriaErroSessao::Estado
        );
        let prematuro = cifrar_bruto(&mut bob, &[CHAT, b'x']);
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&prematuro)),
            CategoriaErroSessao::Protocolo
        );

        let (mut alice, mut bob) = par_verified();
        alice.iniciar_close(MotivoClose::Normal).unwrap();
        assert_eq!(
            alice.enviar_chat("tarde").unwrap_err().categoria(),
            CategoriaErroSessao::Estado
        );
        let tarde = bob.enviar_chat("tarde").unwrap();
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&tarde)),
            CategoriaErroSessao::Protocolo
        );
    }

    #[test]
    fn chat_adulterado_replay_reordenado_removido_e_refletido_falha() {
        let (mut alice, mut bob) = par_verified();
        let mut adulterado = bob.enviar_chat("segredo").unwrap();
        *adulterado.last_mut().unwrap() ^= 1;
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&adulterado)),
            CategoriaErroSessao::Aead
        );
        assert!(alice.processar_ciphertext(&adulterado).is_err());

        let (mut alice, mut bob) = par_verified();
        let replay = bob.enviar_chat("uma vez").unwrap();
        alice.processar_ciphertext(&replay).unwrap();
        assert!(alice.processar_ciphertext(&replay).is_err());

        let (mut alice, mut bob) = par_verified();
        let _removido = bob.enviar_chat("primeiro").unwrap();
        let segundo = bob.enviar_chat("segundo").unwrap();
        assert!(alice.processar_ciphertext(&segundo).is_err());

        let (mut alice, _) = par_verified();
        let refletido = alice.enviar_chat("reflexão").unwrap();
        assert!(alice.processar_ciphertext(&refletido).is_err());
    }

    #[test]
    fn chat_de_outra_sessao_e_type_cifrado_alterado_falham() {
        let (_, mut bob_antigo) = par_verified();
        let antigo = bob_antigo.enviar_chat("sessão antiga").unwrap();
        let (mut alice_nova, _) = par_verified();
        assert!(alice_nova.processar_ciphertext(&antigo).is_err());

        let (mut alice, mut bob) = par_verified();
        let desconhecido = cifrar_bruto(&mut bob, &[0x7f, b'x']);
        assert_eq!(
            categoria_erro(alice.processar_ciphertext(&desconhecido)),
            CategoriaErroSessao::Protocolo
        );
    }

    #[test]
    fn idle_inicia_reseta_e_produz_close_idle_timeout() {
        let inicio = Instant::now();
        let mut idle = ControleIdle::new(Duration::from_secs(10), inicio);
        assert_eq!(idle.deadline, inicio + Duration::from_secs(10));
        idle.registrar_atividade(inicio + Duration::from_secs(3));
        assert_eq!(idle.deadline, inicio + Duration::from_secs(13));

        let (mut alice, mut bob) = par_verified();
        let close = alice.timeout_idle().unwrap();
        assert_eq!(alice.estado(), EstadoSessao::Closing);
        assert!(matches!(
            bob.processar_ciphertext(&close).unwrap(),
            EventoRemoto::Close {
                motivo: MotivoClose::IdleTimeout,
                ..
            }
        ));
    }

    #[test]
    fn comando_sair_exige_correspondencia_exata_apos_crlf() {
        let mut comando = "/sair\r\n".to_owned();
        remover_terminador_linha(&mut comando);
        assert_eq!(comando, "/sair");

        for mensagem in [" /sair\n", "/sair \n", "/SAIR\n"] {
            let mut mensagem = mensagem.to_owned();
            remover_terminador_linha(&mut mensagem);
            assert_ne!(mensagem, "/sair");
        }
    }
}
