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

O estado atual é um laboratório executado em um único processo. Ele realiza um
handshake completo em memória entre Alice e Bob, confirma que ambos obtiveram o
mesmo channel-binding value, formata o handshake hash completo como fingerprint
e inclui testes controlados de adulteração do handshake.

Ainda não existem:

- transporte TCP;
- chat real entre processos;
- GUI ou versão Android;
- anonimato de rede; ou
- suporte para uso em produção.

## Execução

Para executar o laboratório atual:

```console
cargo run
```

Para executar os testes:

```console
cargo test
```

## Documentação de segurança

- [Modelo de ameaças](docs/threat-model.md)
- [Especificação do protocolo](docs/protocol.md)

Conformidade com a especificação e aprovação dos testes não constituem
auditoria criptográfica nem garantia de segurança.

## Licença

Distribuído sob a [MIT License](LICENSE).
