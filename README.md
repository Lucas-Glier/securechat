# SecureChat

SecureChat é um projeto experimental e educacional de mensagens seguras. Ele
está em desenvolvimento inicial, não foi auditado e não está pronto para uso em
produção.

## Objetivo

O projeto busca construir, de forma incremental e auditável, um chat direto
entre duas pessoas enquanto estuda criptografia aplicada, protocolos de rede,
desenvolvimento seguro e testes adversariais.

As propriedades estudadas incluem:

- confidencialidade;
- integridade de mensagens;
- autenticação entre peers;
- forward secrecy;
- proteção contra replay; e
- minimização da persistência de mensagens e segredos de sessão.

## Arquitetura atual

A implementação usa Rust, `snow` 0.10.0 e o Noise Protocol Framework com o
padrão `XX`. A única suíte prevista para a versão 0.1 é:

```text
Noise_XX_25519_ChaChaPoly_SHA256
```

O estado atual executa o handshake Noise XX entre dois processos reais por uma
conexão TCP loopback. As três mensagens do handshake usam frames formados por
um comprimento `u32` big-endian seguido do body, limitado a 8192 bytes. Ambos
os lados concluem o handshake e exibem o mesmo fingerprint completo derivado do
channel-binding value.

Depois do handshake, a sessão permanece `UNVERIFIED` até cada usuário comparar
o fingerprint completo por um canal independente, confirmar localmente a
igualdade e receber um `VERIFY_CONFIRMED` autenticado do peer. Somente as duas
condições levam a `VERIFIED`. Nesse estado, os peers podem trocar mensagens
`CHAT` UTF-8 autenticadas e criptografadas, com conteúdo de 1 a 4096 bytes. O
comando local `/sair` inicia um encerramento autenticado e recíproco com
`CLOSE(NORMAL)`. Uma sessão `VERIFIED` inativa por 15 minutos inicia
`CLOSE(IDLE_TIMEOUT)`.

Ainda não existem:

- histórico, arquivos ou anexos;
- GUI ou versão Android;
- anonimato de rede; ou
- suporte para uso em produção.

## Execução

Em um terminal, inicie o responder:

```console
cargo run -- listen 127.0.0.1:7777
```

Em outro terminal, inicie o initiator:

```console
cargo run -- connect 127.0.0.1:7777
```

Para executar os testes:

```console
cargo test
```

Atualmente existem 49 testes cobrindo o laboratório Noise em memória, framing,
handshake por TCP loopback, verificação explícita, controles criptografados,
`CHAT`, `CLOSE`, idle timeout e cenários adversariais controlados. Entre eles
estão limites de mensagem, UTF-8 inválido, rejeição de frames truncados,
interrupções de conexão, adulteração, replay, reflexão, reordenação e tentativas
de usar mensagens fora do estado correto.

## Documentação de segurança

- [Modelo de ameaças](docs/threat-model.md)
- [Especificação do protocolo](docs/protocol.md)

Conformidade com a especificação e aprovação dos testes não constituem
auditoria criptográfica nem garantia de segurança.

## Licença

Distribuído sob a [MIT License](LICENSE).
