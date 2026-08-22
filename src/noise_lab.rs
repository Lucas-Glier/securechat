use std::fmt::Write as _;
use std::io;

use snow::{Builder, HandshakeState, params::NoiseParams};
use zeroize::Zeroizing;

const PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8; 15] = b"SecureChat-v0.1";
const HANDSHAKE_BUFFER_SIZE: usize = 8192;
const HANDSHAKE_HASH_SIZE: usize = 32;

pub(crate) struct ResultadoLaboratorio {
    alice_handshake_hash: [u8; HANDSHAKE_HASH_SIZE],
    bob_handshake_hash: [u8; HANDSHAKE_HASH_SIZE],
    fingerprint: String,
    payload_lengths: [usize; 3],
}

impl ResultadoLaboratorio {
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn channel_binding_confirmado(&self) -> bool {
        self.alice_handshake_hash == self.bob_handshake_hash
    }

    pub(crate) fn payloads_vazios(&self) -> bool {
        self.payload_lengths == [0, 0, 0]
    }
}

pub(crate) fn executar_handshake_local() -> Result<ResultadoLaboratorio, Box<dyn std::error::Error>>
{
    let (mut alice, mut bob) = criar_participantes()?;

    let payload_lengths = executar_tres_mensagens(&mut alice, &mut bob)?;

    if !alice.is_handshake_finished() || !bob.is_handshake_finished() {
        return Err(io::Error::other("o handshake não terminou nos dois lados").into());
    }

    let alice_handshake_hash = copiar_handshake_hash(&alice)?;
    let bob_handshake_hash = copiar_handshake_hash(&bob)?;

    if alice_handshake_hash != bob_handshake_hash {
        return Err(io::Error::other("os valores de channel binding são diferentes").into());
    }

    let fingerprint = formatar_fingerprint(&alice_handshake_hash);

    Ok(ResultadoLaboratorio {
        alice_handshake_hash,
        bob_handshake_hash,
        fingerprint,
        payload_lengths,
    })
}

fn criar_participantes() -> Result<(HandshakeState, HandshakeState), Box<dyn std::error::Error>> {
    let params: NoiseParams = PROTOCOL_NAME.parse()?;
    let gerador = Builder::new(params.clone());

    let alice_keypair = gerador.generate_keypair()?;
    let bob_keypair = gerador.generate_keypair()?;

    // Somente os buffers privados pertencentes à aplicação recebem esta
    // proteção best-effort. Snow mantém estado interno fora do nosso controle.
    let alice_private = Zeroizing::new(alice_keypair.private);
    let bob_private = Zeroizing::new(bob_keypair.private);

    let alice = Builder::new(params.clone())
        .local_private_key(alice_private.as_slice())?
        .prologue(PROLOGUE)?
        .build_initiator()?;

    let bob = Builder::new(params)
        .local_private_key(bob_private.as_slice())?
        .prologue(PROLOGUE)?
        .build_responder()?;

    Ok((alice, bob))
}

fn executar_tres_mensagens(
    alice: &mut HandshakeState,
    bob: &mut HandshakeState,
) -> Result<[usize; 3], snow::Error> {
    let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
    let mut payload = [0_u8; HANDSHAKE_BUFFER_SIZE];

    // Alice -> Bob: e
    let tamanho = alice.write_message(&[], &mut mensagem)?;
    let payload_1 = bob.read_message(&mensagem[..tamanho], &mut payload)?;

    // Bob -> Alice: e, ee, s, es
    let tamanho = bob.write_message(&[], &mut mensagem)?;
    let payload_2 = alice.read_message(&mensagem[..tamanho], &mut payload)?;

    // Alice -> Bob: s, se
    let tamanho = alice.write_message(&[], &mut mensagem)?;
    let payload_3 = bob.read_message(&mensagem[..tamanho], &mut payload)?;

    Ok([payload_1, payload_2, payload_3])
}

fn copiar_handshake_hash(estado: &HandshakeState) -> Result<[u8; HANDSHAKE_HASH_SIZE], io::Error> {
    estado
        .get_handshake_hash()
        .try_into()
        .map_err(|_| io::Error::other("handshake hash não possui 32 bytes"))
}

fn formatar_fingerprint(hash: &[u8; HANDSHAKE_HASH_SIZE]) -> String {
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
        let resultado = executar_handshake_local().expect("handshake local deve concluir");

        assert_eq!(resultado.payload_lengths, [0, 0, 0]);
        assert_eq!(resultado.alice_handshake_hash.len(), 32);
        assert_eq!(resultado.bob_handshake_hash.len(), 32);
        assert_eq!(resultado.alice_handshake_hash, resultado.bob_handshake_hash);
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
        let primeira = executar_handshake_local().expect("primeira sessão deve concluir");
        let segunda = executar_handshake_local().expect("segunda sessão deve concluir");

        // Este é apenas um teste operacional de chaves e ephemerals novas, não
        // uma prova formal de aleatoriedade ou segurança.
        assert_ne!(primeira.fingerprint, segunda.fingerprint);
    }

    #[test]
    fn adulteracao_no_tag_da_terceira_mensagem_falha_no_read_message_de_bob() {
        let (mut alice, mut bob) = criar_participantes().expect("participantes devem ser criados");
        let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
        let mut payload = [0_u8; HANDSHAKE_BUFFER_SIZE];

        // As duas primeiras mensagens percorrem o caminho honesto.
        let tamanho = alice
            .write_message(&[], &mut mensagem)
            .expect("Alice deve produzir a primeira mensagem");
        assert_eq!(bob.read_message(&mensagem[..tamanho], &mut payload), Ok(0));

        let tamanho = bob
            .write_message(&[], &mut mensagem)
            .expect("Bob deve produzir a segunda mensagem");
        assert_eq!(
            alice.read_message(&mensagem[..tamanho], &mut payload),
            Ok(0)
        );

        // Mallory altera somente o buffer wire entre WriteMessage e
        // ReadMessage. O último byte pertence ao tag AEAD do payload vazio da
        // terceira mensagem. O teste demonstra detecção de adulteração nessa
        // região autenticada e comportamento fail-closed; isoladamente, não
        // prova resistência completa a MITM, proteção de todas as regiões do
        // handshake nem segurança formal de Noise ou ChaCha20-Poly1305.
        let tamanho = alice
            .write_message(&[], &mut mensagem)
            .expect("Alice deve produzir a terceira mensagem");
        mensagem[tamanho - 1] ^= 0x01;

        let resultado = bob.read_message(&mensagem[..tamanho], &mut payload);

        assert!(matches!(resultado, Err(snow::Error::Decrypt)));
        assert!(!bob.is_handshake_finished());
    }

    #[test]
    fn adulteracao_do_primeiro_e_em_claro_falha_ao_ler_segunda_mensagem() {
        let (mut alice, mut bob) = criar_participantes().expect("participantes devem ser criados");
        let mut mensagem = [0_u8; HANDSHAKE_BUFFER_SIZE];
        let mut payload = [0_u8; HANDSHAKE_BUFFER_SIZE];

        let tamanho = alice
            .write_message(&[], &mut mensagem)
            .expect("Alice deve produzir a primeira mensagem");
        assert_eq!(tamanho, 32);

        let original_e: [u8; 32] = mensagem[..tamanho]
            .try_into()
            .expect("a primeira mensagem deve conter um public key X25519");

        let params: NoiseParams = PROTOCOL_NAME
            .parse()
            .expect("protocol name deve ser válido");
        let mallory_keypair = Builder::new(params)
            .generate_keypair()
            .expect("Mallory deve gerar um keypair X25519 válido");
        let mallory_private = Zeroizing::new(mallory_keypair.private);

        assert_eq!(mallory_keypair.public.len(), 32);
        assert_ne!(mallory_keypair.public.as_slice(), original_e.as_slice());

        // Mallory substitui exclusivamente os bytes wire entre WriteMessage e
        // ReadMessage. O primeiro `e` ainda não tem autenticação imediata: Bob
        // o aceita, incorpora o valor substituto ao transcript com MixHash e o
        // usa na contribuição `ee`. Isso altera tanto `h` quanto as chaves
        // derivadas. A inconsistência é detectada posteriormente pela AEAD da
        // segunda mensagem, e Alice falha de modo fechado.
        //
        // O teste não prova isoladamente resistência completa a MITM, segurança
        // formal de Noise, X25519 ou ChaCha20-Poly1305, nem somente transcript
        // binding ou somente divergência de `ee`, pois ambos são afetados.
        mensagem[..tamanho].copy_from_slice(&mallory_keypair.public);

        assert_eq!(bob.read_message(&mensagem[..tamanho], &mut payload), Ok(0));

        let tamanho = bob
            .write_message(&[], &mut mensagem)
            .expect("Bob deve produzir a segunda mensagem normalmente");
        let resultado = alice.read_message(&mensagem[..tamanho], &mut payload);

        assert!(matches!(resultado, Err(snow::Error::Decrypt)));
        assert!(!alice.is_handshake_finished());

        drop(mallory_private);
    }
}
