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

Depois do handshake, a sessão continua `UNVERIFIED`. O laboratório cria e
descarta o estado de transporte sem enviar mensagens de aplicação.

Ainda não existem:

- `VERIFY_CONFIRMED` ou transição para `VERIFIED`;
- mensagens `CHAT`;
- encerramento autenticado por `CLOSE`;
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

Atualmente existem 18 testes cobrindo o laboratório Noise em memória, framing,
handshake por TCP loopback e cenários adversariais controlados. Entre eles estão
a rejeição de frames inválidos ou truncados, interrupções de conexão, payloads
de handshake não vazios e adulterações das mensagens Noise.

## Documentação de segurança

- [Modelo de ameaças](docs/threat-model.md)
- [Especificação do protocolo](docs/protocol.md)

Conformidade com a especificação e aprovação dos testes não constituem
auditoria criptográfica nem garantia de segurança.

## Licença

Distribuído sob a [MIT License](LICENSE).
