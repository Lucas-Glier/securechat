# SecureChat

## Idioma do projeto

O idioma oficial do projeto é português brasileiro (`pt-BR`).

- A documentação do projeto e novas especificações devem ser escritas em
  português brasileiro.
- Comentários explicativos devem ser escritos preferencialmente em português
  brasileiro.
- Relatórios e explicações destinados ao desenvolvedor devem ser escritos em
  português brasileiro, para que as decisões possam ser acompanhadas e
  auditadas pelo desenvolvedor humano.
- Nomes oficiais de protocolos, algoritmos, bibliotecas, APIs, tipos, funções,
  constantes, formatos wire e identificadores de código não devem ser
  traduzidos.
- Identificadores técnicos como
  `Noise_XX_25519_ChaChaPoly_SHA256`, `TransportState`,
  `get_handshake_hash()`, `VERIFY_CONFIRMED`, `CHAT`, `CLOSE`, `VERIFIED` e
  `FAILED` permanecem inalterados quando apropriado.

SecureChat é um projeto educacional de código aberto para mensagens seguras.

O objetivo é construir um chat privado entre duas pessoas enquanto se estudam
criptografia aplicada, redes, desenvolvimento seguro de software e testes de
segurança.

## Objetivos centrais de segurança

O aplicativo deve buscar fornecer:

- Confidencialidade
- Integridade das mensagens
- Autenticidade do peer
- Forward secrecy
- Proteção contra replay
- Metadados mínimos
- Nenhuma persistência intencional do histórico de mensagens

Quando uma conversa/sessão terminar, mensagens em texto simples e segredos da
sessão não devem ser intencionalmente persistidos em armazenamento permanente.

O código-fonte deve ser completamente auditável. A segurança não deve depender
de o código-fonte permanecer secreto.

## Regras de criptografia

- NUNCA inventar primitivas criptográficas.
- Usar bibliotecas criptográficas estabelecidas e auditadas.
- Nunca implementar algoritmos de criptografia próprios.
- Nunca implementar algoritmos de hash próprios.
- Nunca implementar geradores de números aleatórios próprios.
- Nunca fixar chaves criptográficas no código.
- Nunca registrar mensagens em texto simples em logs.
- Nunca registrar chaves privadas ou chaves de sessão em logs.
- Nunca reduzir silenciosamente a segurança.
- Falhas de autenticação devem falhar de modo fechado.
- Falhas de integridade devem rejeitar a mensagem afetada.
- Alterações no protocolo devem ser documentadas.

## Regras de desenvolvimento

Este também é um projeto educacional.

Não tomar grandes decisões arquiteturais silenciosamente.

Para alterações sensíveis à segurança:

1. Explicar o problema.
2. Explicar a solução proposta.
3. Explicar as hipóteses de segurança.
4. Implementar a menor alteração razoável.
5. Adicionar testes.
6. Executar os testes.
7. Relatar o que foi alterado.

Preferir commits e alterações pequenos e revisáveis.

Não implementar funcionalidades não relacionadas sem solicitação.

## Testes de segurança

O projeto incluirá um laboratório de segurança isolado para testar o protocolo
e a implementação do SecureChat.

Os testes de segurança podem incluir simulações controladas de:

- adulteração de mensagens
- replay
- personificação
- condições de man-in-the-middle
- substituição de chaves
- pacotes malformados
- interrupção da conexão
- testes de persistência/artefatos

Esses testes devem ter como alvo somente o ambiente local de testes do
SecureChat.

Toda vulnerabilidade descoberta deve ser documentada com:

- causa
- impacto
- reprodução no ambiente de testes
- mitigação
- teste de regressão

## Escopo inicial

A versão 0.1 deve ser intencionalmente pequena.

Inicialmente, ela deve oferecer suporte a:

- dois peers
- interface de linha de comando
- conexão direta
- handshake autenticado
- estabelecimento seguro de sessão
- mensagens criptografadas
- mensagens autenticadas
- proteção contra replay
- encerramento limpo da sessão
- nenhuma persistência intencional do histórico de mensagens

Fora do escopo da primeira versão:

- Android
- GUI
- chats em grupo
- contas
- banco de dados central de mensagens
- implantação em produção
- anonimato de rede
- resistência à censura
- roteamento semelhante ao Tor

## Importante

Não afirmar que algo é "seguro" apenas porque a implementação parece correta.

As propriedades de segurança devem ser sustentadas por testes ou raciocínio
documentado.
