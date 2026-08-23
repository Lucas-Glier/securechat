use std::fmt::Write as _;
use std::io;

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use zeroize::Zeroizing;

use crate::DynError;

pub const PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const PROLOGUE: &[u8; 15] = b"SecureChat-v0.1";
pub const HANDSHAKE_BUFFER_SIZE: usize = 8192;
const HANDSHAKE_HASH_SIZE: usize = 32;

pub struct CanalNoise {
    handshake_hash: [u8; HANDSHAKE_HASH_SIZE],
    fingerprint: String,
    payload_lengths: [usize; 3],
    transport: TransportState,
}

impl CanalNoise {
    pub fn handshake_hash(&self) -> &[u8; HANDSHAKE_HASH_SIZE] {
        &self.handshake_hash
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn payloads_vazios(&self) -> bool {
        self.payload_lengths == [0, 0, 0]
    }

    pub(crate) fn transport_mut(&mut self) -> &mut TransportState {
        &mut self.transport
    }
}

pub fn criar_initiator() -> Result<HandshakeState, DynError> {
    criar_estado(true)
}

pub fn criar_responder() -> Result<HandshakeState, DynError> {
    criar_estado(false)
}

fn criar_estado(initiator: bool) -> Result<HandshakeState, DynError> {
    let params: NoiseParams = PROTOCOL_NAME.parse()?;
    let keypair = Builder::new(params.clone()).generate_keypair()?;

    // A chave privada controlada pela aplicação recebe limpeza best-effort.
    // Snow mantém cópias internas cujo apagamento não controlamos.
    let private = Zeroizing::new(keypair.private);
    let builder = Builder::new(params)
        .local_private_key(private.as_slice())?
        .prologue(PROLOGUE)?;

    if initiator {
        Ok(builder.build_initiator()?)
    } else {
        Ok(builder.build_responder()?)
    }
}

pub fn finalizar_handshake(
    estado: HandshakeState,
    payload_lengths: [usize; 3],
) -> Result<CanalNoise, DynError> {
    if !estado.is_handshake_finished() {
        return Err(io::Error::other("o handshake Noise não terminou").into());
    }

    let handshake_hash = copiar_handshake_hash(&estado)?;
    let fingerprint = formatar_fingerprint(&handshake_hash);
    let transport = estado.into_transport_mode()?;

    Ok(CanalNoise {
        handshake_hash,
        fingerprint,
        payload_lengths,
        transport,
    })
}

fn copiar_handshake_hash(estado: &HandshakeState) -> Result<[u8; HANDSHAKE_HASH_SIZE], io::Error> {
    estado
        .get_handshake_hash()
        .try_into()
        .map_err(|_| io::Error::other("handshake hash não possui 32 bytes"))
}

pub fn formatar_fingerprint(hash: &[u8; HANDSHAKE_HASH_SIZE]) -> String {
    let mut fingerprint = String::with_capacity(71);

    for (indice, byte) in hash.iter().enumerate() {
        if indice > 0 && indice % 4 == 0 {
            fingerprint.push('-');
        }
        write!(&mut fingerprint, "{byte:02x}").expect("escrever em String não falha");
    }

    fingerprint
}

#[cfg(test)]
fn executar_handshake_local() -> Result<(CanalNoise, CanalNoise), DynError> {
    let mut alice = criar_initiator()?;
    let mut bob = criar_responder()?;
    let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
    let mut payload = [0_u8; HANDSHAKE_BUFFER_SIZE];

    let tamanho = alice.write_message(&[], &mut mensagem)?;
    let payload_1_bob = bob.read_message(&mensagem[..tamanho], &mut payload)?;
    let tamanho = bob.write_message(&[], &mut mensagem)?;
    let payload_2_alice = alice.read_message(&mensagem[..tamanho], &mut payload)?;
    let tamanho = alice.write_message(&[], &mut mensagem)?;
    let payload_3_bob = bob.read_message(&mensagem[..tamanho], &mut payload)?;

    let alice = finalizar_handshake(alice, [0, payload_2_alice, 0])?;
    let bob = finalizar_handshake(bob, [payload_1_bob, 0, payload_3_bob])?;
    Ok((alice, bob))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usa_protocol_name_e_prologue_exatos() {
        assert_eq!(PROTOCOL_NAME, "Noise_XX_25519_ChaChaPoly_SHA256");
        assert_eq!(PROLOGUE, b"SecureChat-v0.1");
        assert_eq!(
            PROLOGUE,
            &[
                0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x43, 0x68, 0x61, 0x74, 0x2d, 0x76, 0x30, 0x2e,
                0x31,
            ]
        );
    }

    #[test]
    fn conclui_xx_com_payloads_vazios_e_channel_binding_identico() {
        let (alice, bob) = executar_handshake_local().expect("handshake local deve concluir");
        assert!(alice.payloads_vazios());
        assert!(bob.payloads_vazios());
        assert_eq!(alice.handshake_hash().len(), 32);
        assert_eq!(bob.handshake_hash().len(), 32);
        assert_eq!(alice.handshake_hash(), bob.handshake_hash());
    }

    #[test]
    fn fingerprint_tem_formato_canonico_e_round_trip_sem_perdas() {
        let hash = std::array::from_fn(|indice| indice as u8);
        let fingerprint = formatar_fingerprint(&hash);
        assert_eq!(fingerprint.len(), 71);
        assert_eq!(fingerprint.matches('-').count(), 7);
        assert!(fingerprint.bytes().enumerate().all(|(indice, byte)| {
            if matches!(indice, 8 | 17 | 26 | 35 | 44 | 53 | 62) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        }));

        let hexadecimal: String = fingerprint
            .chars()
            .filter(|caractere| *caractere != '-')
            .collect();
        let mut recuperado = [0_u8; HANDSHAKE_HASH_SIZE];
        for (indice, destino) in recuperado.iter_mut().enumerate() {
            *destino = u8::from_str_radix(&hexadecimal[indice * 2..indice * 2 + 2], 16)
                .expect("fingerprint deve conter hexadecimal válido");
        }
        assert_eq!(recuperado, hash);
    }

    #[test]
    fn sessoes_independentes_normalmente_produzem_fingerprints_diferentes() {
        let (primeira, _) = executar_handshake_local().expect("primeira sessão deve concluir");
        let (segunda, _) = executar_handshake_local().expect("segunda sessão deve concluir");
        // Este é apenas um teste operacional, não uma prova de aleatoriedade.
        assert_ne!(primeira.fingerprint(), segunda.fingerprint());
    }

    #[test]
    fn adulteracao_no_tag_da_terceira_mensagem_falha_no_read_message_de_bob() {
        let mut alice = criar_initiator().expect("Alice deve ser criada");
        let mut bob = criar_responder().expect("Bob deve ser criado");
        let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
        let mut payload = [0_u8; HANDSHAKE_BUFFER_SIZE];

        let tamanho = alice.write_message(&[], &mut mensagem).expect("mensagem 1");
        assert_eq!(bob.read_message(&mensagem[..tamanho], &mut payload), Ok(0));
        let tamanho = bob.write_message(&[], &mut mensagem).expect("mensagem 2");
        assert_eq!(
            alice.read_message(&mensagem[..tamanho], &mut payload),
            Ok(0)
        );

        // Mallory altera somente o wire numa região protegida por AEAD. Isto
        // demonstra detecção e falha fechada, não segurança formal completa.
        let tamanho = alice.write_message(&[], &mut mensagem).expect("mensagem 3");
        mensagem[tamanho - 1] ^= 0x01;
        let resultado = bob.read_message(&mensagem[..tamanho], &mut payload);
        assert!(matches!(resultado, Err(snow::Error::Decrypt)));
        assert!(!bob.is_handshake_finished());
    }

    #[test]
    fn adulteracao_do_primeiro_e_em_claro_falha_ao_ler_segunda_mensagem() {
        let mut alice = criar_initiator().expect("Alice deve ser criada");
        let mut bob = criar_responder().expect("Bob deve ser criado");
        let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
        let mut payload = [0_u8; HANDSHAKE_BUFFER_SIZE];

        let tamanho = alice.write_message(&[], &mut mensagem).expect("mensagem 1");
        assert_eq!(tamanho, 32);
        let original_e: [u8; 32] = mensagem[..tamanho].try_into().expect("public key X25519");
        let params: NoiseParams = PROTOCOL_NAME.parse().expect("protocol name válido");
        let mallory_keypair = Builder::new(params)
            .generate_keypair()
            .expect("keypair válido");
        let mallory_private = Zeroizing::new(mallory_keypair.private);
        assert_eq!(mallory_keypair.public.len(), 32);
        assert_ne!(mallory_keypair.public.as_slice(), original_e.as_slice());

        // A substituição altera MixHash e `ee`; a segunda mensagem detecta a
        // divergência. O teste não isola as causas nem prova segurança formal.
        mensagem[..tamanho].copy_from_slice(&mallory_keypair.public);
        assert_eq!(bob.read_message(&mensagem[..tamanho], &mut payload), Ok(0));
        let tamanho = bob.write_message(&[], &mut mensagem).expect("mensagem 2");
        let resultado = alice.read_message(&mensagem[..tamanho], &mut payload);
        assert!(matches!(resultado, Err(snow::Error::Decrypt)));
        assert!(!alice.is_handshake_finished());
        drop(mallory_private);
    }
}
