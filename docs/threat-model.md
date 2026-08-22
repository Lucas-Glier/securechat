# Modelo de Ameaças do SecureChat v0.1

Este documento define o escopo, as hipóteses, as ameaças e as afirmações de
segurança pretendidas para o SecureChat v0.1. Ele é um objetivo de projeto, não
uma evidência de que a implementação é segura. Cada afirmação de segurança deve
ser sustentada por raciocínio documentado, testes ou ambos.

## 1. Escopo

O SecureChat v0.1 é um chat educacional, de código aberto e por linha de comando
para exatamente dois peers. Os peers se comunicam por uma conexão direta. Não
há contas, servidor central, banco central de mensagens nem entrega offline.

O escopo de segurança começa quando os processos estabelecem uma conexão e
tentam um handshake autenticado. Ele inclui autenticação do handshake,
estabelecimento de chaves, transporte de mensagens, tratamento de replay e
encerramento do estado criptográfico da sessão.

A rede é hostil. Confidencialidade e autenticidade devem resistir a um atacante
de rede somente quando:

- ambos os endpoints satisfazem as hipóteses de confiança deste documento;
- os peers concluem a verificação explícita das informações de autenticação
  derivadas do handshake;
- o protocolo e a biblioteca criptográfica satisfazem suas hipóteses; e
- a implementação está correta.

O SecureChat v0.1 não afirma proteger texto simples contra um endpoint
comprometido enquanto ele é digitado, processado ou exibido.

## 2. Ativos

O SecureChat v0.1 pretende proteger:

- conteúdo em texto simples digitado, recebido, processado ou exibido;
- segredos de sessão, inclusive chaves e material secreto intermediário;
- autenticidade e integridade dos dados do handshake;
- autenticidade, integridade e informações de ordenação das mensagens;
- a vinculação entre a autenticação verificada e a sessão estabelecida;
- estado criptográfico efêmero, como nonces, contadores e estado de replay; e
- metadados sob controle do aplicativo, inclusive logs e arquivos persistentes.

Material de identidade de longo prazo, caso introduzido posteriormente, também
é sensível. Seu ciclo de vida e persistência devem ser especificados antes da
implementação.

## 3. Objetivos de segurança

### Confidencialidade

Um atacante de rede não deve recuperar texto simples a partir do tráfego
capturado, respeitadas as hipóteses deste documento.

### Integridade e autenticidade das mensagens

Uma mensagem só pode ser aceita e exibida como legítima se o protocolo a
autenticar como originada na sessão verificada e confirmar que seu conteúdo
protegido não foi alterado. Mensagens modificadas, forjadas, malformadas ou não
autenticadas devem ser rejeitadas e não exibidas como legítimas.

### Autenticidade do peer e resistência a MITM

O handshake deve vincular a sessão a informações que ambos os peers verificam
explicitamente antes de confiar nela. Divergência, verificação incompleta ou
falha de autenticação deve falhar de modo fechado: o aplicativo não pode entrar
em chat confiável nem apresentar mensagens como autenticadas.

Isso depende de comparar as informações corretas por um canal autêntico ou
pessoalmente. Se os usuários pularem, entenderem incorretamente ou confirmarem
falsamente a etapa, o SecureChat não garante proteção contra MITM ativo.

### Forward secrecy

Forward secrecy é um objetivo: comprometimento posterior de segredo de
autenticação de longo prazo não deve, sozinho, revelar sessões concluídas. A
garantia depende do protocolo, do descarte correto do estado e da ausência de
texto simples ou segredos retidos. Não protege sessão cujo endpoint ou estado
ativo foi comprometido durante seu uso.

### Proteção contra replay

Mensagem já aceita não deve ser aceita novamente como nova. Mensagem de outra
sessão não deve ser aceita na atual. Duplicatas, reordenação e atraso devem ter
política definida na especificação do protocolo.

### Minimização de dados

O SecureChat deve minimizar metadados sob seu controle e não persistir
intencionalmente mensagens ou segredos de sessão. Isso não afirma anonimato,
resistência a análise de tráfego nem eliminação forense.

### Nenhum downgrade silencioso

O aplicativo não pode trocar silenciosamente propriedade, algoritmo, etapa de
verificação ou modo autenticado obrigatório por alternativa mais fraca.
Parâmetros inválidos ou não suportados devem falhar de modo fechado.

## 4. Capacidades do adversário

O adversário pode:

- observar todo o tráfego;
- interceptar, atrasar, descartar, repetir, injetar, reordenar, truncar ou
  modificar pacotes;
- conectar-se a qualquer peer e personificar o outro;
- executar handshakes separados com ambos em um MITM ativo;
- substituir valores do handshake ou informações de autenticação;
- enviar mensagens malformadas, superdimensionadas, inesperadas ou fora de
  estado;
- interromper e restaurar a conectividade;
- reter tráfego capturado indefinidamente;
- conhecer todo o código-fonte, documentação, testes e dependências; e
- usar recursos substanciais, presumindo-se apenas que não quebre primitivas
  padronizadas corretas dentro de seus limites documentados.

O projeto segue o princípio de Kerckhoffs: nenhuma propriedade depende de
manter secretos código, protocolo, formatos ou algoritmos.

## 5. Hipóteses de confiança

O SecureChat v0.1 presume que:

- dispositivos, sistemas operacionais, processos, terminais e caminhos de
  entrada são confiáveis durante a conversa;
- o endpoint tem fonte funcional de aleatoriedade criptograficamente segura;
- a biblioteca criptográfica cumpre suas propriedades e é usada corretamente;
- os peers podem comparar informações por método autêntico independente da
  rede do SecureChat;
- ambos comparam toda a informação exigida e rejeitam divergências;
- os usuários não divulgam texto simples nem segredos; e
- a plataforma fornece isolamento e controles de acesso básicos.

Se um endpoint já estiver comprometido, malware pode ler texto simples, alterar
entrada, falsificar a apresentação da autenticação ou roubar estado ativo. O
SecureChat não garante confidencialidade, integridade ou autenticidade nessa
situção.

## 6. Fronteiras de confiança

1. **Usuário, terminal e processo local.** Texto simples e verificação cruzam
   essa fronteira; o terminal está parcialmente fora do controle do projeto.
2. **Processo e sistema operacional.** O aplicativo depende do sistema para
   isolamento, memória, rede, aleatoriedade, arquivos e dispositivos. Swap,
   crash dumps e hibernação podem copiar dados.
3. **SecureChat e biblioteca criptográfica.** Primitivas e verificações são
   confiadas à biblioteca; seleção e uso corretos são do aplicativo.
4. **Endpoint e rede hostil.** Todo dado de rede é controlado pelo atacante até
   parsing seguro e autenticação. Endereço ou conexão não prova identidade.
5. **Handshake e sessão confiável.** A conexão permanece não confiável até o
   sucesso do handshake e da verificação explícita de ambos os peers.

## 7. Ameaças e mitigações

As mitigações são requisitos ou direções, não prova de conformidade futura.

### Divulgação passiva

**Ameaça:** captura de tráfego para recuperar mensagens.

**Mitigação obrigatória:** usar criptografia autenticada e estabelecimento de
sessão reconhecidos, não transmitir texto simples ou segredos e usar bibliotecas
estabelecidas e auditadas.

**Risco residual:** temporização, tamanhos, endereços, duração e outros
metadados permanecem visíveis; comprometimento do endpoint anula a proteção.

### MITM ativo e personificação

**Ameaça:** interceptação, sessões independentes ou substituição do handshake.

**Mitigação obrigatória:** vincular informação visível ao handshake e à sessão,
exigir verificação explícita de ambos, abortar por divergência ou ausência e não
oferecer fallback não verificado.

**Risco residual:** não há proteção se usuários aprovarem informação incorreta
ou se o canal independente for controlado pelo atacante.

### Modificação, falsificação e injeção

**Ameaça:** alteração de ciphertext ou cabeçalhos, fabricação ou injeção.

**Mitigação obrigatória:** autenticar cada mensagem e metadado relevante;
rejeitar antes de exibir texto simples e invalidar a sessão quando inseguro
continuar.

### Replay e substituição entre sessões

**Ameaça:** reenvio na sessão ou movimentação entre sessões/direções.

**Mitigação obrigatória:** vincular mensagens à sessão e direção, manter estado
autenticado de sequência/replay e rejeitar duplicatas e valores fora da regra.

### Reordenação, atraso, truncamento e interrupção

**Ameaça:** reordenar, atrasar, suprimir, truncar ou interromper para enganar
sobre o estado.

**Mitigação obrigatória:** definir ordenação e estados autenticados; detectar
ordem e encerramento inválidos quando possível; não apresentar interrupção como
encerramento autenticado.

**Risco residual:** não é possível provar envio de mensagem descartada, forçar
entrega nem sempre diferenciar ataque de falha comum.

### Entrada malformada e esgotamento de recursos

**Ameaça:** frames, estados ou volumes maliciosos causarem parsing inseguro,
falha ou esgotamento.

**Mitigação obrigatória:** tratar rede como não confiável; limitar comprimentos
e alocações; validar framing, tipos, valores e estados; falhar sem expor
segredos; testar entradas malformadas e grandes.

**Risco residual:** limites não eliminam negação de serviço.

### Downgrade ou uso criptográfico incorreto

**Ameaça:** parâmetros fracos, reutilização de chave/nonce ou construção
incorreta.

**Mitigação obrigatória:** construção estabelecida, biblioteca auditada,
negociação e transcript autenticados, parâmetros fixos e falha fechada. Nunca
implementar criptografia, hash ou RNG próprios. Documentar mudanças.

### Persistência de segredo ou texto simples

**Ameaça:** dados permanecerem em logs, arquivos, temporários ou estado
reutilizável.

**Mitigação obrigatória:** não registrar mensagens ou chaves, não criar
histórico, manter segredos em estado volátil e descartá-los em todos os caminhos
de término.

**Risco residual:** sistema, runtime, hardware, terminal, backups ou análise
forense podem reter cópias. Não se afirma eliminação forense.

### Comprometimento posterior de autenticação de longo prazo

**Ameaça:** segredo persistente posterior permitir recuperar tráfego antigo.

**Mitigação obrigatória:** usar estabelecimento com forward secrecy, não
derivar chaves antigas só de segredos persistentes e descartar estado concluído.

**Risco residual:** forward secrecy não corrige captura de texto, chaves ou
estado ativo durante a sessão.

## 8. Não objetivos explícitos

O SecureChat v0.1 não fornece:

- anonimato ou ocultação de IP;
- resistência a análise de tráfego, temporização, tamanho, volume ou duração;
- resistência à censura ou roteamento como Tor;
- entrega, uptime ou proteção garantida contra negação de serviço;
- proteção em endpoint comprometido;
- proteção contra peer malicioso que copie conteúdo recebido legitimamente;
- eliminação forense de memória, armazenamento, terminais ou backups;
- segurança pós-comprometimento durante sessão ativa, salvo protocolo futuro;
- grupos, contas, GUI, Android, banco central, offline ou produção; ou
- prova de segurança apenas por aparente conformidade com este documento.

## 9. Modelo de persistência e análise forense

Mensagens e segredos não devem ser persistidos intencionalmente. Não haverá
histórico nem texto simples, chaves privadas ou de sessão em logs, diagnósticos
ou erros.

Durante a sessão, esses dados necessariamente existem na memória. No término e
em erros tratados, referências devem ser descartadas prontamente e recursos de
limpeza da biblioteca usados quando oferecerem garantia significativa. Buffers
não devem ser retidos para sessões futuras.

Isso limita persistência deliberada, mas não estabelece eliminação forense.
Dados podem permanecer em:

- swap ou paginação;
- crash/core dumps ou telemetria;
- hibernação;
- scrollback, logs ou captura do terminal;
- memória após liberação lógica;
- journals, temporários, backups ou snapshots; e
- monitoramento por dispositivo, hypervisor ou sistema operacional.

Só se afirma controle sobre comportamento especificado e testado. Orientações
de sistema podem ser documentadas, mas garantias mais fortes exigem controle
demonstrado da plataforma.

Chaves de identidade persistentes futuras devem ser separadas de segredos de
sessão e ter armazenamento, acesso, rotação, exclusão e comprometimento
projetados antes da introdução.

## 10. Modelo de disponibilidade

A disponibilidade é de melhor esforço. O aplicativo deve tratar perdas, dados
malformados e erros com segurança e evitar falhas ou consumo ilimitado.

O atacante sempre pode descartar tudo, impedir conexão, atrasar, desconectar ou
consumir recursos. Não se garante estabelecimento, entrega nem tempestividade.
Mecanismos criptográficos não serão enfraquecidos para recuperar disponibilidade.

## 11. Afirmações de segurança que pretendemos testar

O laboratório local isolado deve testar que:

- payloads capturados não contêm texto simples;
- alteração de conteúdo ou metadado protegido causa rejeição e nada ilegítimo
  é exibido;
- injeções e falsificações são rejeitadas;
- replays são rejeitados;
- mensagens não atravessam sessões ou direções;
- ordem inválida segue a política documentada;
- MITM ou substituição muda a autenticação e não produz sessão confiável quando
  a comparação é correta;
- divergência, incompletude, parâmetros não suportados e handshakes inválidos
  falham fechados sem downgrade;
- pacotes malformados, grandes, truncados ou fora de estado são seguros;
- interrupção não é apresentada como término autenticado;
- logs e arquivos não contêm mensagens nem segredos;
- estado é descartado em término e falhas na medida controlável; e
- comprometimento de segredo persistente não revela sessões concluídas sob as
  hipóteses de forward secrecy selecionadas.

Testes só podem atingir o ambiente local isolado. Eles sustentam propriedades
específicas, não uma afirmação irrestrita de segurança.

## 12. Perguntas de projeto em aberto

Antes da implementação, `docs/protocol.md` ou outra documentação deve resolver:

- construção estabelecida de troca autenticada de chaves;
- biblioteca, algoritmos, parâmetros e versões;
- informação exata comparada, derivação do transcript/identidades e interação;
- identidade persistente, efêmera, segredo compartilhado ou outro modelo, com
  ciclo de vida se persistente;
- limites do primeiro contato e apresentação do estado não verificado;
- identificador, chaves direcionais, transcript binding, confirmação e domain
  separation;
- framing, limites, cabeçalhos, nonce, sequência e replay;
- política para ordem, duplicata, lacuna, contador, autenticação e má formação;
- encerramento autenticado e apresentação de truncamento, timeout e EOF;
- metadados inevitáveis e minimizáveis;
- linguagem/runtime e controles de segredo;
- controles e limitações de swap, dumps, hibernação, terminal e memória; e
- mapeamento de cada objetivo a raciocínio, vetores e testes adversariais e de
  regressão.
