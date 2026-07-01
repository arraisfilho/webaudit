# WebAudit

Ferramenta de auditoria de servidores web em **Bash puro**. Analisa DNS, TCP,
HTTP/HTTPS, TLS, certificados, cabeçalhos de segurança, identifica o software
e o sistema operacional do servidor e correlaciona a versão detectada com
CVEs conhecidas — tudo a partir da linha de comando, sem runtime externo.

[![CI](https://github.com/SEU_USUARIO/webaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/SEU_USUARIO/webaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Shell: bash](https://img.shields.io/badge/shell-bash-1f425f.svg)](https://www.gnu.org/software/bash/)

---

## Sumário

- [Destaques](#destaques)
- [Dependências](#dependências)
- [Instalação](#instalação)
- [Uso rápido](#uso-rápido)
- [Exemplo de saída](#exemplo-de-saída)
- [Parâmetros](#parâmetros)
- [Formatos de saída](#formatos-de-saída)
- [Modo scanner](#modo-scanner)
- [Configuração](#configuração)
- [Fontes de dados](#fontes-de-dados)
- [Arquitetura](#arquitetura)
- [Testes e qualidade](#testes-e-qualidade)
- [Códigos de saída](#códigos-de-saída)
- [FAQ](#faq)
- [Roadmap](#roadmap)
- [Contribuição](#contribuição)
- [Licença](#licença)

---

## Destaques

- **Bash puro**: sem Python, Node, Go ou Rust. Dependências obrigatórias
  mínimas (`bash`, `curl`, `openssl`).
- **Modular**: cada camada de análise é um módulo independente em `lib/`.
- **TLS completo**: versões de 1.0 a 1.3, cipher, ALPN, forward secrecy,
  compressão, session ticket, reuso de sessão e OCSP stapling/Must-Staple.
- **Certificado**: emissor, SAN, wildcard, validade, algoritmos, verificação
  de hostname e cadeia.
- **Segurança**: pontuação de HSTS, CSP, X-Content-Type-Options, X-Frame-
  Options, Referrer-Policy, Permissions-Policy e cabeçalhos COEP/COOP/CORP.
- **CVEs**: consulta a NVD 2.0 e OSV.dev com cache local.
- **Seis formatos de saída**: texto, JSON, CSV, HTML, Markdown e YAML.
- **Scanner**: audita listas de hosts a partir de um arquivo.
- **Portável**: Linux e macOS.
- **ShellCheck-clean** e com suíte de testes.

## Dependências

**Obrigatórias**

| Ferramenta | Uso                                  |
|------------|--------------------------------------|
| `bash`     | 4.0+ (recomendado 5.x)               |
| `curl`     | Requisições HTTP/HTTPS               |
| `openssl`  | Handshake TLS e análise de cadeia    |

**Opcionais** (habilitam funcionalidades extras)

| Ferramenta | Uso                                                  |
|------------|------------------------------------------------------|
| `jq`       | Parsing robusto das APIs de CVE/versão               |
| `dig`/`host` | Consultas DNS mais completas (fallback: `getent`)  |
| `timeout`/`gtimeout` | Limite de tempo por operação               |
| `column`   | Alinhamento de algumas saídas                        |

## Instalação

### Via `make`

```sh
git clone https://github.com/arraisfilho/webaudit.git
cd webaudit
sudo make install          # instala em /usr/local (PREFIX ajustável)
webaudit exemplo.com
```

Para desinstalar: `sudo make uninstall`.

### Execução direta (sem instalar)

```sh
git clone https://github.com/arraisfilho/webaudit.git
cd webaudit
./webaudit.sh exemplo.com
```

## Uso rápido

```sh
# Auditoria básica (saída em texto)
webaudit exemplo.com

# Vários hosts
webaudit exemplo.com outro.com terceiro.net

# Relatório JSON para um arquivo
webaudit --json exemplo.com > relatorio.json

# Relatório HTML de uma lista de hosts
webaudit --html hosts.txt > relatorio.html

# Verboso, com timeout maior e porta HTTPS customizada
webaudit -v -t 15 exemplo.com:8443
```

## Exemplo de saída

```
══════════════════════════════════════════════

Host............ cloudflare.com
IPv4............ 104.16.132.229 104.16.133.229
IPv6............

HTTP............ OK
HTTPS........... OK

TLS............. TLSv1.3
Cipher.......... TLS_AES_256_GCM_SHA384

Certificado..... OK
Emissor......... (emissor do certificado)
Algoritmo....... ECDSA256
Expira.em....... 250 dias

Servidor........ cloudflare
Fingerprint..... Cloudflare(edge) http2

HSTS............ OK
CSP............. OK
Seguranca....... 10/11

Tempo........... 1.00 segundos

══════════════════════════════════════════════
```

> Os valores exatos variam conforme o alvo e o ambiente de rede.

## Parâmetros

```
USO:
  webaudit [OPÇÕES] <host|url> [host2 ...]
  webaudit [OPÇÕES] <arquivo_de_hosts.txt>

OPÇÕES:
  -o, --output FORMATO   text (padrão), json, csv, html, markdown, yaml
      --json/--csv/--html/--markdown/--yaml   atalhos para -o

  -p, --port-http N      Porta HTTP (padrão: 80)
  -P, --port-https N     Porta HTTPS (padrão: 443)
  -t, --timeout SEG      Timeout por operação (padrão: 10)
  -A, --user-agent STR   User-Agent das requisições

      --proxy URL        Proxy para HTTP/HTTPS (curl -x)
      --no-cache         Desabilita cache local
      --no-cve           Desabilita consulta de CVEs
      --nvd-key KEY      API key para a NVD (NIST)
      --github-token TOK Token para GitHub Security Advisories

      --log ARQUIVO      Grava log estruturado no arquivo
  -c, --config ARQUIVO   Caminho para config.conf

  -v, --verbose          Modo detalhado (todos os campos e CVEs)
  -q, --quiet            Modo silencioso (apenas OK/WARNING/CRITICAL)
      --no-color         Desabilita cores ANSI

  -h, --help             Mostra a ajuda
  -V, --version          Mostra a versão
```

Também se aplica a variável de ambiente padrão `NO_COLOR` para desativar cores.

## Formatos de saída

Detalhes completos em [`docs/OUTPUT_FORMATS.md`](docs/OUTPUT_FORMATS.md).

| Flag         | Uso típico                                    |
|--------------|-----------------------------------------------|
| (padrão)     | Leitura no terminal                           |
| `--json`     | Integração com outras ferramentas             |
| `--csv`      | Planilhas e relatórios tabulares              |
| `--yaml`     | Versionamento / pipelines                     |
| `--markdown` | Issues, wikis, relatórios                     |
| `--html`     | Relatório autocontido para navegador          |

## Modo scanner

Passe um arquivo de texto com um host por linha (linhas iniciadas por `#` e
linhas em branco são ignoradas):

```
# hosts.txt
exemplo.com
https://outro.com
terceiro.net:8443
```

```sh
webaudit --json hosts.txt > relatorio.json   # array JSON
webaudit --html hosts.txt > relatorio.html   # documento único
webaudit -q hosts.txt                        # resumo por host
```

O código de saída reflete a **pior** nota entre todos os hosts.

## Configuração

Copie `config.conf` e ajuste os valores; aponte com `-c`:

```sh
webaudit -c ./meu-config.conf exemplo.com
```

As flags de linha de comando têm precedência sobre o arquivo de configuração.
Chaves de API (NVD, GitHub) podem ficar no arquivo (mantenha-o fora do controle
de versão) ou ser passadas por flag.

## Fontes de dados

- **[endoflife.date](https://endoflife.date)** — versão mais recente de cada
  produto para a comparação de atualização.
- **[NVD 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)** — base de
  CVEs do NIST. Sem chave: limite reduzido de requisições; com `--nvd-key`,
  limite maior. Solicite uma chave gratuita em nvd.nist.gov.
- **[OSV.dev](https://osv.dev)** — vulnerabilidades por ecossistema/pacote.

Todas as respostas são armazenadas em cache local com TTL para reduzir
chamadas repetidas.

## Arquitetura

Visão detalhada em [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
webaudit.sh          orquestrador (config, CLI, loop de alvos, agregação)
lib/
  colors.sh utils.sh cli.sh
  dns.sh tcp.sh http.sh tls.sh cert.sh headers.sh security.sh
  server.sh fingerprint.sh versions.sh cve.sh
  report.sh json.sh csv.sh html.sh markdown.sh
tests/run_tests.sh   suíte de testes
docs/                documentação
```

Os módulos trocam dados por um _result store_ em memória com chaves
`modulo.campo` (ex.: `tls.negotiated`, `cert.days_left`).

## Testes e qualidade

```sh
make lint                       # shellcheck -x em todos os scripts
make test                       # testes unitários (sem rede)
WEBAUDIT_TEST_NET=1 make test   # inclui testes de integração (rede)
make check                      # valida a sintaxe (bash -n)
```

O projeto mantém `shellcheck -x` sem avisos (as poucas supressões estão
documentadas em `.shellcheckrc`) e roda CI em Linux e macOS.

## Códigos de saída

| Código | Significado   |
|--------|---------------|
| 0      | OK            |
| 1      | WARNING       |
| 2      | CRITICAL      |
| 3      | Erro interno  |

## FAQ

**Preciso de root?** Não para auditar. Apenas `make install` em prefixos do
sistema (como `/usr/local`) requer privilégios.

**Funciona sem `jq`?** Sim. Há _fallback_ sem `jq`, mas o parsing das APIs de
CVE é mais robusto quando `jq` está presente.

**O `Emissor` aparece como um gateway/proxy corporativo.** Se a rede
intercepta TLS (proxy MITM), o certificado observado será o do proxy, não o do
servidor final. Rode a partir de uma rede sem interceptação para resultados
fiéis.

**Por que a versão aparece como "mascarada"?** Muitos servidores omitem a
versão no cabeçalho `Server` (boa prática). Sem versão, não é possível
comparar atualização nem correlacionar CVEs — e isso é sinalizado na saída.

**A ferramenta é intrusiva?** Não. Faz apenas coletas passivas e consultas de
leitura. Ainda assim, audite somente alvos autorizados (ver `SECURITY.md`).

**Suporta IPv6/portas não padrão?** Sim. Aceita `host:porta` e URLs completas;
a porta HTTPS pode ser ajustada com `-P`.

## Roadmap

- Descoberta e teste de HTTP/3 (QUIC) quando o `curl` suportar.
- Verificação de CAA e DNSSEC.
- Correlação de CVE por CPE além de busca por palavra-chave.
- Saída SARIF para integração com plataformas de segurança.
- Paralelização opcional no modo scanner.

## Contribuição

Contribuições são bem-vindas. Leia [`CONTRIBUTING.md`](CONTRIBUTING.md) e o
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Para vulnerabilidades, siga o
[`SECURITY.md`](SECURITY.md).

## Licença

Distribuído sob a licença [MIT](LICENSE).
