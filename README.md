# Privacy Extension

Extensão para Firefox (WebExtension / Manifest V2) que analisa a
página atual e mostra, em tempo real, os principais vetores de
rastreamento usados pela web moderna.

Trabalho desenvolvido para o **Roteiro 4** da disciplina.

## O que a extensão detecta

- **Domínios de terceira parte** chamados durante a navegação,
  com o tipo do recurso (script, iframe, imagem, xhr, ...).
- **Cookies** classificados por parte (1ª / 3ª), duração
  (sessão / persistente) e **supercookies** (ETag e HSTS em
  terceira parte).
- **Web Storage**: chaves e tamanhos de `localStorage` e
  `sessionStorage`, além dos bancos `IndexedDB` de cada origem.
- **Fingerprinting** de Canvas, WebGL e AudioContext, monitorando
  as APIs mais usadas (`toDataURL`, `getImageData`, `getParameter`
  com `UNMASKED_*`, `WEBGL_debug_renderer_info`, `createOscillator`,
  `createDynamicsCompressor`, `createAnalyser`).
- **Cookie syncing**: valores que parecem identificadores e
  aparecem em duas ou mais origens de terceira parte na mesma
  página.
- **Hijacking**: scripts conhecidos por hooking ou mineração
  (BeEF `hook.js`, `coinhive`, `cryptonight`, `webminerpool`) e
  redirecionamentos cross-origin no `main_frame`.
- **Privacy Score** numérico (0–100) com conceito A–F, calculado
  a partir das penalidades descritas mais abaixo.

## Instalação

```bash
git clone https://github.com/andrefrugis/Roteiro4.git
```

1. Abra o Firefox em `about:debugging#/runtime/this-firefox`.
2. Clique em **Carregar extensão temporária**.
3. Selecione o `manifest.json` na raiz do projeto.

A extensão fica disponível até o Firefox ser fechado. Para
recarregar após editar um arquivo basta clicar em **Recarregar**
nessa mesma tela.

## Uso

Visite um site qualquer e clique no ícone do escudo. O popup tem
seis abas: visão geral, terceiros, cookies, fingerprint, storage
e hijacking. O número que aparece sobre o ícone (badge) mostra
quantos domínios de terceira parte foram observados na aba —
verde até 5, amarelo até 15 e vermelho acima disso.

Sugestões para testar:
                                              
 `cnn.com`, `uol.com.br`                           
 `amiunique.org/fingerprint`, `coveryourtracks.eff.org` 
 `browserleaks.com/canvas`, `browserleaks.com/webgl` 

## Privacy Score

A pontuação começa em 100 e desconta penalidades. A justificativa
para cada peso é o quanto aquele sinal contribui para identificar
ou seguir o usuário entre páginas.

```
Score = max(0, 100 − Σ penalidades)
```

| Sinal                                          | Penalidade        | Teto |
| ---------------------------------------------- | ----------------- | ----:|
| Cada domínio de terceira parte                 | −2                |  −30 |
| Tracker conhecido entre os terceiros           | −3 adicional      |  −15 |
| Cookie de terceira parte                       | −2 cada           |  −20 |
| Cookie persistente                             | −0,5 cada         |   −5 |
| Supercookie (ETag) em 3ª parte                 | −10 fixo se ≥1    |  −10 |
| Canvas fingerprinting                          | −8 se detectado   |   −8 |
| WebGL fingerprinting                           | −8 se detectado   |   −8 |
| Audio fingerprinting                           | −8 se detectado   |   −8 |
| Cookie syncing                                 | −10 fixo se ≥1    |  −10 |
| Script suspeito (BeEF, miner)                  | −15 cada          |  −30 |
| Redirecionamento cross-origin no `main_frame`  | −5 cada           |  −15 |
| `localStorage` em origem de terceira parte     | −2 cada           |  −10 |

Conceitos: **A** 85–100 (Excelente), **B** 70–84 (Bom),
**C** 55–69 (Médio), **D** 35–54 (Ruim), **F** 0–34 (Crítico).

Os pesos refletem três ideias: rastreamento volumétrico
(terceiros, cookies) pontua proporcionalmente; vetores que
identificam unicamente o navegador (fingerprinting, supercookie)
têm peso fixo porque uma única chamada já basta para identificar;
e sinais associados a comprometimento (BeEF, miner) recebem o
maior peso individual.

## Arquitetura

```
privacy_extension/
├── manifest.json
├── background.js        coleta de requisições, headers, score
├── content-script.js    injeta o inject.js e lê Web Storage
├── inject.js            roda no contexto da página e observa as
│                        APIs de fingerprinting
├── popup.html/.css/.js  interface do popup
└── icons/
```


## Limitações conhecidas

- A identificação do domínio registrável usa uma lista interna de
  TLDs compostos, não a Public Suffix List completa. Por isso
  `google.com` e `google.com.br` aparecem como domínios
  diferentes, o que tecnicamente está correto mas pode inflar a
  contagem em sites brasileiros.
- A detecção de cookie syncing é heurística: olha valores longos
  em query strings que se repetem entre origens. Sincronismos
  feitos via POST não são vistos.
- A lista de trackers conhecidos é curta e ilustrativa; em
  produção seria substituída por listas como EasyPrivacy.
- O monitoramento começa quando a extensão é carregada. Para
  sites já abertos é preciso recarregar a aba.
