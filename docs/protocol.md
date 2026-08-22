# Especificação do Protocolo SecureChat v0.1

Status: especificação inicial do protocolo

Este documento define o protocolo wire interoperável e o comportamento de
sessão do SecureChat v0.1. É uma especificação, não prova de segurança. As
implementações também devem seguir `AGENTS.md` e `docs/threat-model.md`.

Os termos normativos significam:

- **DEVE** (`MUST`) e **OBRIGATÓRIO** (`REQUIRED`): requisito absoluto;
- **NÃO DEVE** (`MUST NOT`): proibição absoluta;
- **DEVERIA** (`SHOULD`): recomendado, salvo razão documentada e analisada;
- **NÃO DEVERIA** (`SHOULD NOT`): desaconselhado, salvo razão documentada;
- **PODE** (`MAY`): comportamento opcional permitido.

## 1. Escopo e decisões fixas

O SecureChat v0.1 é um chat CLI entre duas pessoas, orientado a sessão, sobre
uma conexão TCP ordenada e direta. Não há servidor central, contas, identidade
persistente, entrega offline nem histórico.

A implementação é em Rust e usa `snow` 0.10.x. Ao iniciar a implementação, uma
versão 0.10.x exata DEVE ser fixada; intervalo flutuante não basta.

O único protocolo Noise aceito é:

```text
Noise_XX_25519_ChaChaPoly_SHA256
```

Ele significa Noise revision 34, padrão `XX`, X25519, ChaCha20-Poly1305 e
SHA-256. Não há negociação de suíte, padrão, versão ou algoritmo. Alternativa,
fallback ou downgrade NÃO DEVE ser aceito.

Após o handshake, usa-se `snow::TransportState`, nunca
`StatelessTransportState`. Não se expõem nonces, não se cria outro sistema de
nonce nem outra camada de criptografia.

## 2. Terminologia e papéis

O **iniciador** abre TCP e envia a primeira mensagem XX. O **respondedor**
aceita TCP e a recebe. O conector é sempre iniciador e o listener sempre
respondedor; simultaneous open não existe na v0.1.

**Chave de autenticação da sessão** é a chave na posição `s` de Noise. Apesar
do termo “static” de Noise, não é identidade persistente: cada peer gera um
novo par por tentativa e não o persiste.

**Chave efêmera Noise** ocupa `e`; Snow DEVE gerar uma nova a cada handshake e
ela nunca pode ser reutilizada.

**Fingerprint** é a codificação do hash final definida na Seção 6. **Canal
independente autenticado** é um meio não controlado pelo caminho SecureChat,
como comparação presencial ou chamada de voz/vídeo autenticada separadamente.

## 3. Constantes do protocolo

| Nome | Valor |
| --- | ---: |
| Nome Noise | `Noise_XX_25519_ChaChaPoly_SHA256` |
| Prologue | bytes ASCII de `SecureChat-v0.1` |
| Prefixo TCP | 4 bytes |
| Corpo máximo do frame | 8192 bytes |
| Conteúdo máximo de chat | 4096 bytes |
| Timeout do handshake | 15 segundos |
| Timeout de verificação | 5 minutos |
| Timeout ocioso em `VERIFIED` | 15 minutos |
| Timeout de frame em progresso | 15 segundos |
| Timeout de resposta a `CLOSE` | 5 segundos |

O prologue são exatamente estes 15 bytes, sem BOM, tamanho, terminador, newline
ou aspas:

```text
53 65 63 75 72 65 43 68 61 74 2d 76 30 2e 31
```

Ambos fornecem essa codificação de `SecureChat-v0.1` a Snow antes do handshake.
O nome Noise vincula padrão e algoritmos; o prologue vincula aplicação e
versão. Timeouts usam relógio monotônico. Limite local menor para conexão TCP
PODE existir sem alterar o wire.

## 4. Framing TCP

Cada mensagem Noise de handshake ou transport ocupa exatamente um frame:

```text
+----------------------+---------------------------+
| body_length (u32be)  | body (body_length bytes)  |
+----------------------+---------------------------+
|       4 bytes        |         1..8192           |
+----------------------+---------------------------+
```

`body_length` é u32 em network byte order e exclui o prefixo. `body` é uma
mensagem Noise completa. O receptor DEVE ler e validar o prefixo antes de
alocar/redimensionar. Zero ou valor acima de 8192 é falha de protocolo e nunca
pode orientar alocação.

Após chegar qualquer byte do prefixo, o frame inteiro DEVE chegar em 15
segundos. EOF parcial, timeout ou truncamento é interrupção de rede, salvo se os
bytes já provarem violação.

Frames são processados serialmente. Um frame não pode conter duas mensagens,
parte de uma, padding externo ou dado sem framing. Bytes seguintes iniciam novo
prefixo. O limite de 8192 reduz memória e parsing e fica bem abaixo de 65535.

## 5. Handshake Noise XX

Antes dele, cada peer DEVE fixar o papel, configurar nome e prologue exatos,
usar a CSPRNG suportada por Snow, gerar novo par X25519 `s` e não reutilizar
chave de tentativa anterior.

Todos os payloads do handshake são vazios. Dados, versão, confirmação e chat
NÃO DEVEM aparecer neles.

```text
-> e
<- e, ee, s, es
-> s, se
```

São exatamente três frames:

1. iniciador: `WriteMessage` vazio e envia `-> e`;
2. respondedor: lê, executa `ReadMessage`, depois `WriteMessage` vazio e envia
   `<- e, ee, s, es`;
3. iniciador: lê, executa `ReadMessage`, depois `WriteMessage` vazio e envia
   `-> s, se`; o respondedor lê e executa `ReadMessage`.

O iniciador não envia o terceiro antes de processar o segundo; o respondedor
não envia primeiro nem aceita handshake extra. Tudo deve terminar em 15
segundos totais desde `HANDSHAKING`.

São falhas: erro Noise de parsing, DH, criptografia ou autenticação; payload
recuperado não vazio; passo incompatível com papel/estado; frame inválido;
protocolo/prologue diferente; ou não concluir exatamente após três mensagens.

Após processar a última mensagem e Snow indicar conclusão, cada lado DEVE
copiar todos os 32 bytes de `get_handshake_hash()` antes de consumir
`HandshakeState` com `into_transport_mode()`. O `TransportState` resultante
mantém cifras direcionais e nonces implícitos. O estado passa a `UNVERIFIED`,
não `VERIFIED`.

## 6. Fingerprint e verificação

### 6.1 Fingerprint canônico

O fingerprint codifica sem perdas todos os 32 bytes retornados, na mesma ordem.
Cada byte vira dois caracteres hexadecimais minúsculos (`0-9`, `a-f`), com
hífen após cada quatro bytes:

```text
hhhhhhhh-hhhhhhhh-hhhhhhhh-hhhhhhhh-hhhhhhhh-hhhhhhhh-hhhhhhhh-hhhhhhhh
```

São 64 caracteres hexadecimais e sete hífens. Espaço só PODE ser apresentado
fora do valor. É proibido truncar, abreviar, substituir, resumir ou derivar SAS.

O display DEVE mostrar `UNVERIFIED` e instruir a comparar o valor inteiro por
canal independente autenticado. Enviá-lo pela própria conexão não é comparação
independente.

### 6.2 Justificativa criptográfica do channel binding

Na especificação Noise, `h` incorpora todos os dados enviados e recebidos no
handshake, e `GetHandshakeHash()` expõe o valor final como identificador único
da sessão para `channel binding`. Em `XX`, os tokens `es` e `se`, combinados
com a transmissão protegida de `s`, autenticam a posse das chaves `s`; Noise,
sozinho, não decide a qual pessoa essas chaves pertencem. Essas semânticas são
definidas nas seções [Handshake state](https://noiseprotocol.org/noise.html#the-handshakestate-object),
[Channel binding](https://noiseprotocol.org/noise.html#channel-binding) e
[Interactive patterns](https://noiseprotocol.org/noise.html#interactive-patterns)
da especificação oficial do Noise Protocol Framework.

Na v0.1, as chaves `s` descartáveis autenticam somente esta sessão. A associação
com os humanos é feita pela comparação externa de todos os 256 bits de `h`.
Se dois usuários confiáveis obtêm valores integrais iguais pelo canal
independente, eles têm evidência criptográfica de participação no mesmo
handshake Noise, sob a resistência a colisão de SHA-256, a correção de Noise e
Snow e a autenticidade do canal de comparação. Um MITM que termine duas sessões
XX distintas produz transcripts e valores `h` distintos; um atacante que apenas
retransmita o mesmo handshake não obtém as chaves de transporte. Isso não
autentica sessões futuras nem protege comparação omitida, incompleta ou
controlada pelo atacante. Também depende de os endpoints exibirem fielmente o
valor retornado; um endpoint comprometido pode falsificar a apresentação, como
já limitado em `docs/threat-model.md`.

### 6.3 Confirmação local e do peer

O usuário escolhe explicitamente: correspondência completa, divergência ou
cancelamento/recusa. Ausência não confirma; nada pode preselecionar, inferir,
automatizar, lembrar ou reutilizar confirmação.

Ao confirmar, define-se `local_confirmed = true` e envia-se exatamente um
`VERIFY_CONFIRMED` criptografado. Divergência termina em falha; recusa/cancelamento
termina como cancelamento. Se utilizável, PODE tentar uma vez `CLOSE` com
`VERIFICATION_ABORTED`, sem esperar.

Ao validar `VERIFY_CONFIRMED` em `UNVERIFIED`, define-se
`peer_confirmed = true`. Isso prova apenas envio pelo endpoint remoto no canal,
não a ação humana. A confirmação local continua autoritativa.

Só há transição para `VERIFIED` quando:

```text
local_confirmed == true
peer_confirmed  == true
```

A ordem é livre. Em `UNVERIFIED`, entrada de chat fica desabilitada e não pode
ser enfileirada, armazenada, criptografada, transmitida ou exibida. Só
`VERIFY_CONFIRMED` e `CLOSE` são válidos. A verificação termina em cinco minutos;
receber/enviar confirmação não reinicia o prazo. No timeout, DEVERIA tentar
`CLOSE(VERIFICATION_ABORTED)`, fechar e descartar sem esperar. Toda nova conexão
exige novas chaves, fingerprint e comparação.

## 7. Máquina de estados

- `DISCONNECTED`: sem TCP ou estado;
- `CONNECTED`: TCP existe, Noise não começou;
- `HANDSHAKING`: XX em andamento;
- `UNVERIFIED`: transport existe, coordenação incompleta;
- `VERIFIED`: ambas as confirmações locais foram coordenadas;
- `CLOSING`: fechamento autenticado em andamento;
- `CLOSED`: terminal não criptográfico, estado descartado;
- `FAILED`: terminal por protocolo, criptografia ou verificação, estado descartado.

| Estado | Evento | Próximo |
| --- | --- | --- |
| `DISCONNECTED` | TCP estabelecido | `CONNECTED` |
| `CONNECTED` | configuração e chaves prontas | `HANDSHAKING` |
| `HANDSHAKING` | Noise e transport concluídos | `UNVERIFIED` |
| `UNVERIFIED` | ambos os flags verdadeiros | `VERIFIED` |
| `UNVERIFIED`/`VERIFIED` | close local ou remoto válido | `CLOSING` |
| `CLOSING` | `CLOSE` recíproco válido após envio local | `CLOSED` |
| qualquer não terminal | cancelamento local/interrupção comum | `CLOSED` |
| `HANDSHAKING` ou posterior | falha criptográfica/protocolo | `FAILED` |
| `UNVERIFIED` | fingerprint divergente | `FAILED` |

`CONNECTED` é breve e não aceita frame de aplicação. Autenticação inválida,
replay que falhe, nonce esgotado, mensagem inesperada, payload inválido ou
violação de estado vai imediatamente a `FAILED`, fecha socket e descarta tudo.
Nunca ressincronizar, reiniciar contador, tentar outra chave ou continuar.

`CLOSED` e `FAILED` são terminais. Reconexão reinicia com novas chaves. Um
motivo terminal separado DEVE distinguir clean close, EOF, timeout,
cancelamento, recusa, divergência, autenticação e violação sem expor segredos.

## 8. Payloads de aplicação criptografados

Cada payload vira exatamente uma mensagem Noise transport e um frame. O
primeiro byte plaintext é o tipo; todo cabeçalho fica dentro da AEAD.

| Tipo | Nome | Formato plaintext | Estado de recepção |
| ---: | --- | --- | --- |
| `0x01` | `VERIFY_CONFIRMED` | somente tipo | `UNVERIFIED` |
| `0x02` | `CHAT` | `type || utf8_content` | `VERIFIED` |
| `0x03` | `CLOSE` | `type || reason` | `UNVERIFIED`, `VERIFIED`, `CLOSING` |

Não há extensão ou opcional. Payload vazio, tipo desconhecido, tamanho,
encoding ou estado inválido é falha.

### 8.1 `VERIFY_CONFIRMED`

É exatamente `01`, enviado uma vez após confirmação local. Corpo deve ser
vazio. Segundo controle novo ou fora de `UNVERIFIED` falha. Replay de ciphertext
deve falhar antes pela autenticação do nonce avançado.

### 8.2 `CHAT`

```text
+-------------+--------------------------+
| type = 0x02 | UTF-8 message content    |
+-------------+--------------------------+
|   1 byte    |       1..4096 bytes      |
+-------------+--------------------------+
```

O tamanho é o payload menos um, sem tamanho interno. Deve ser UTF-8 válido e
ter 1..4096 bytes; não há normalização. Um payload é uma mensagem e só existe
em `VERIFIED`; não há fragmentação lógica. O ciphertext máximo é 4113 bytes
(1 + 4096 + tag 16), dentro de 8192.

### 8.3 `CLOSE`

É exatamente `type = 0x03 || reason (u8)`:

| Valor | Nome | Significado |
| ---: | --- | --- |
| `0x00` | `NORMAL` | encerramento ordenado pelo usuário |
| `0x01` | `VERIFICATION_ABORTED` | recusa, cancelamento, divergência ou timeout |
| `0x02` | `IDLE_TIMEOUT` | sessão atingiu limite ocioso |

Reason é informativo e não substitui observação local. Valor ou tamanho
desconhecido falha.

## 9. Transport e replay

Chamar criptografia uma vez por payload e decriptação uma vez por frame, em
ordem TCP. `TransportState` mantém estados direcionais e nonces implícitos. É
proibido transmitir/alterar nonce, reutilizar estado em outra conexão,
decriptar frame duas vezes, inverter direções ou continuar após esgotamento.

Duplicar, repetir, retirar/reinserir ou reordenar ciphertext desalinha nonce e
falha AEAD. Nenhum plaintext é usado; entra `FAILED`, fecha e descarta. Descarte
de bytes/EOF apenas impede entrega e nunca autoriza ressincronização.

## 10. Encerramento autenticado

### 10.1 Iniciado localmente

Em `UNVERIFIED`/`VERIFIED`: parar chat, enviar um `CLOSE`, marcar
`local_close_sent`, entrar `CLOSING`, rejeitar `CHAT`/`VERIFY_CONFIRMED` e esperar
até cinco segundos. `CLOSE` remoto válido registra encerramento autenticado,
fecha, descarta e vai a `CLOSED`. EOF/timeout registra interrupção não limpa e
NÃO DEVE afirmar recebimento/autenticação pelo peer.

### 10.2 Iniciado pelo peer

Ao receber `CLOSE` válido: parar chat, registrar close autenticado, entrar
`CLOSING`, responder uma vez com mesmo reason se ainda não enviou, fechar após
write ou erro, descartar e ir a `CLOSED`. O recebimento prova o envio remoto
naquela sessão, não a entrega da resposta.

### 10.3 Outros casos

- EOF/timeout: interrupção não autenticada;
- cancelamento antes de transport: fechar e `CLOSED`;
- cancelamento em `UNVERIFIED`: tentativa opcional de
  `CLOSE(VERIFICATION_ABORTED)` e fechamento sem espera;
- autenticação/protocolo: `FAILED` imediato, sem erro criptografado ou `CLOSE`;
- fingerprint divergente: registrar falha, tentativa opcional de `CLOSE` ainda
  utilizável, descartar e `FAILED` sem espera.

O atacante pode descartar `CLOSE`; não se garante término limpo nem se distingue
descarte malicioso de falha.

## 11. Limites, timeouts e ociosidade

- 8192 limita memória controlada pelo atacante;
- 4096 limita plaintext e terminal;
- payload de handshake vazio elimina caminho de dado fraco;
- controles de tamanho exato evitam ambiguidade;
- handshake: 15 segundos totais;
- verificação: 5 minutos totais, sem reset por confirmação;
- frame: 15 segundos desde o primeiro byte, sem reset por novos bytes;
- em `VERIFIED`: 15 minutos desde a última mensagem autenticada completa
  enviada ou recebida; bytes parciais/não autenticados e texto local não
  reiniciam. Ao expirar, `CLOSE(IDLE_TIMEOUT)`;
- não há keepalive/ping/tráfego automático;
- após `CLOSE`: 5 segundos por resposta.

Os limites reduzem retenção de segredos e recursos abandonados; relógios dos
peers não precisam expirar juntos.

## 12. Tratamento de erros

### 12.1 Falhas de protocolo/criptografia

Exigem `FAILED`, fechamento e descarte: erro Noise/DH/AEAD; nonce esgotado;
replay/reordenação com falha; tamanho de frame inválido; frame fora de estado;
handshake fora de ordem ou payload não vazio; aplicação vazia, grande,
malformada, desconhecida ou fora de estado; UTF-8 inválido; confirmação nova
duplicada; chat fora de `VERIFIED`; negociação, downgrade ou ressincronização.

Nada é recuperável na conexão. Não procurar novo frame, trocar suíte, pular
ciphertext, resetar Noise ou exibir recuperação parcial.

### 12.2 Interrupção comum

EOF, reset, peer inalcançável, frame parcial e timeout vão a `CLOSED` após
descarte. Não são close autenticado nem automaticamente ataque.

### 12.3 Cancelamento local

Não é falha criptográfica. Antes de transport, fecha e vai a `CLOSED`; depois,
segue tentativa de close e vai a `CLOSED`. Divergência explícita vai a `FAILED`.
Erros/logs só contêm categoria e contexto público, nunca plaintext, chaves,
estado secreto ou payload decriptado.

## 13. Persistência e ciclo de vida

Não há histórico. Mensagens, chaves `s`, `e`, segredos de handshake/transport e
payloads decriptados NÃO DEVEM ser gravados. Isso inclui logs, tracing,
diagnóstico, panic, crash reporting configurado, temporários e testes. O
fingerprint é público, mas NÃO DEVERIA persistir por não haver continuidade.

Buffers próprios DEVERIAM usar `zeroize` quando significativo e evitar cópias,
realocações, `Debug`, serialização e passagem entre tasks.

Em todo término: parar tasks com acesso; descartar estado Snow; zeroizar buffers
próprios suportados; descartar chaves e plaintext; nunca reutilizar estado.

Isso não é eliminação forense. Descarte/zeroização não prova que Snow,
compilador, registradores, alocações, allocator, OS, swap, dumps, hibernação,
terminal, virtualização ou hardware apagaram cópias. Snow 0.10.x não documenta
zeroização geral de estado interno. Essa limitação DEVE ser declarada.

## 14. Invariantes testáveis

| Regra | Invariante |
| --- | --- |
| Protocolo fixo | outro nome nunca é construído/aceito |
| Prologue | bytes diferentes falham handshake |
| Chaves frescas | tentativas produzem chaves públicas diferentes com RNG válido |
| Efêmeras frescas | handshakes produzem primeiros `e` diferentes; vetores determinísticos separados |
| XX exato | somente três frames na ordem por papel |
| Payload vazio | payload recuperado não vazio termina |
| Channel binding | peers honestos obtêm mesmos 32 bytes |
| Fingerprint completo | parsing recupera 32 bytes e display tem 64 hex |
| Sem SAS | nenhum caminho aceita/exibe truncamento |
| Gate | chat falha até ambos flags verdadeiros |
| Coordenação | qualquer flag falso impede `VERIFIED` |
| Verificação | divergência, recusa e timeout não verificam |
| Limite | 0 e >8192 rejeitados antes de alocar |
| Completude | parcial nunca chega como mensagem completa |
| Cabeçalho autenticado | alterar tipo/reason falha AEAD |
| Chat | 4096 aceita; 4097, vazio e UTF-8 inválido rejeitam |
| Direção | ciphertext de uma direção falha na outra |
| Replay | ciphertext aceito repetido falha sem duplicar display |
| Ordem | troca falha sem exibir frame falho |
| Fail closed | erro AEAD encerra e ignora frames posteriores |
| Sem resync | remover ciphertext faz o próximo falhar |
| Close | `CLOSE` válido é autenticado; EOF não |
| Truncamento | close descartado não é alegado |
| Descarte | terminal torna uso criptográfico impossível |
| Persistência | artefatos/logs não contêm sentinelas |
| Prazos | todos expiram nos limites com tolerância do scheduler |

## 15. Matriz de testes adversariais

Somente o laboratório local isolado pode ser alvo.

| Propriedade | Mecanismo | Teste esperado |
| --- | --- | --- |
| Confidencialidade | XX/ChaChaPoly | capturar sentinela e confirmar ausência no wire/log |
| Handshake | transcript/AEAD | alterar cada byte; falhar ou mudar fingerprint |
| MITM | comparação integral | proxy com dois XX; fingerprints divergem |
| Downgrade | nome/prologue fixos | suíte/prologue/negociação alternativos não verificam |
| Integridade | ChaChaPoly | alterar ciphertext/tag/header; nada é exibido |
| Injeção | estado/AEAD | injetar frame aleatório; falhar fechado |
| Replay | nonce implícito | repetir cada tipo; falhar sem repetir ação |
| Ordem | TCP + nonce | trocar frames; falhar no primeiro deslocado |
| Sessão | chaves frescas | frame antigo falha em sessão nova |
| Direção | cifras direcionais | refletir ciphertext; falhar |
| Gate | dois flags | tentar chat com nenhuma/só uma confirmação |
| Limite humano | decisão local | confirmação remota primeiro mantém `UNVERIFIED` |
| Framing | u32be/8192 | 0, 8193, `0xffffffff`, parciais e duas mensagens |
| Parser | formatos exatos | vazio, tipo/reason extra, UTF-8/tamanho inválido |
| Close | close recíproco | descartar cada close e usar EOF; não alegar recebimento |
| Interrupção | terminal | cortar após cada byte; nunca retomar estado |
| Recursos | timeouts | slow-drip e stall em cada estado |
| Persistência | sem histórico | sentinelas em todos os términos e inspeção de artefatos |
| Forward secrecy | `ee` fresco | vetores/frescor; documentar limite de teste absoluto |

Testes sustentam apenas propriedades sob suas condições, não segurança
irrestrita.

## 16. Interoperabilidade

Implementações devem concordar sem negociação em: papéis TCP; nome e revision;
prologue; payloads vazios; ordem XX; u32be e 8192; momento de obter `h`;
fingerprint; tipos/tamanhos; flags; transport direcional; UTF-8/4096; reasons e
close; falhas; timeouts.

Devem existir vetores determinísticos da suíte e teste de duas implementações
para handshake, fingerprint, confirmação mútua, chat bidirecional e close.

## 17. Garantias e limitações

Sob as hipóteses do threat model, comparação correta, segurança das primitivas
e Snow e implementação correta, pretende-se: confidencialidade/integridade;
detecção de MITM por comparação integral independente; rejeição de alteração,
replay e ordem inválida; forward secrecy de XX se estado não for comprometido;
close autenticado quando recebido; e nenhuma persistência intencional.

Não se garante: autenticação se comparação for pulada/incompleta/falsa ou canal
for hostil; identidade/continuidade; endpoint comprometido; entrega,
disponibilidade ou close entregue; anonimato/análise de tráfego; recuperação
pós-comprometimento; eliminação forense; nem segurança só por conformidade ou
testes.

## 18. Questões de versões futuras

- identidade persistente e continuidade;
- SAS estabelecido e revisado em lugar do fingerprint integral;
- ratchet com segurança pós-comprometimento;
- padding e redução de metadados;
- outros transportes e entrega fora de ordem;
- agilidade e negociação resistente a downgrade;
- implementação Noise auditada ou auditoria de Snow;
- controles de memória específicos da plataforma; e
- grupos, contas, servidores, offline, anonimato ou censura.

Nada disso permite variar o comportamento fixo da v0.1.
