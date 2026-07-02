# Arquitetura

O WebAudit é organizado como um orquestrador (`webaudit.sh`) que carrega
bibliotecas independentes em `lib/`. Cada biblioteca é um módulo com
responsabilidade única e expõe uma função pública `MODULO::run` (quando
participa do pipeline de coleta) além de funções internas prefixadas com `_`.

## Fluxo de execução

```
main
 ├─ load_config            (config.conf; flags têm precedência)
 ├─ cli::parse / validate  (interpreta argumentos)
 ├─ deps::check_runtime    (valida dependências e sugere instalação)
 └─ para cada alvo:
     audit_one
      ├─ normalize_target  (host[:porta], remove esquema/caminho)
      ├─ dns::run
      ├─ tcp::run
      ├─ http::run         (define WEBAUDIT_RAW_HEADERS, WEBAUDIT_BASE_URL)
      ├─ headers::run
      ├─ tls::run          (define WEBAUDIT_TLS_DUMP)
      ├─ cert::run         (define WEBAUDIT_CERT_PEM)
      ├─ security::run
      ├─ server::run
      ├─ fingerprint::run
      ├─ versions::run     (endoflife.date)
      ├─ cve::run          (NVD 2.0 / OSV.dev)
      └─ report::emit      (text | json | csv | html | markdown | yaml)
```

## Módulos

| Arquivo            | Responsabilidade                                            |
|--------------------|-------------------------------------------------------------|
| `colors.sh`        | Cores ANSI; respeita `NO_COLOR` e ausência de TTY.          |
| `utils.sh`         | Plataforma, tempo, timeout, escapes, logging, cache, store. |
| `cli.sh`           | Versão, ajuda, parsing e validação de argumentos.           |
| `deps.sh`          | Checagem de dependências e instruções de instalação.        |
| `dns.sh`           | Resolução A/AAAA/CNAME/MX/TXT/NS/PTR e detecção de CDN.      |
| `tcp.sh`           | Conectividade nas portas HTTP/HTTPS e latência.             |
| `http.sh`          | Requisições, redirecionamentos, métodos, HTTP/2 e HTTP/3.   |
| `tls.sh`           | Versões TLS, cipher, ALPN, PFS, OCSP, reuso de sessão.      |
| `cert.sh`          | Análise do certificado e da cadeia.                         |
| `headers.sh`       | Cabeçalhos gerais (Server, Cache-Control, ETag, etc.).      |
| `security.sh`      | Pontuação dos cabeçalhos de segurança.                      |
| `server.sh`        | Identificação do software e do sistema operacional.         |
| `fingerprint.sh`   | Heurísticas de identificação de stack.                      |
| `versions.sh`      | Comparação com a versão mais recente (endoflife.date).      |
| `cve.sh`           | Consulta de CVEs (NVD 2.0 e OSV.dev) com cache.             |
| `report.sh`        | Renderização em texto e despacho para os demais formatos.   |
| `json.sh` / `csv.sh` / `html.sh` / `markdown.sh` | Renderizadores por formato.   |

## Estado compartilhado

Os módulos comunicam-se por um _result store_ em memória, definido em
`utils.sh`:

- `utils::result_set <chave> <valor>` grava um resultado.
- `utils::result_get <chave>` recupera.
- `utils::result_has <chave>` verifica existência.
- `utils::result_reset` limpa entre alvos.

As chaves seguem o padrão `modulo.campo` (ex.: `tls.negotiated`,
`cert.days_left`, `sec.score`). Alguns dumps brutos reaproveitados entre
módulos são expostos como variáveis globais (`WEBAUDIT_RAW_HEADERS`,
`WEBAUDIT_TLS_DUMP`, `WEBAUDIT_CERT_PEM`) para evitar novas conexões.

Internamente, o store usa arrays indexados paralelos (`chave` e `valor`) em
vez de arrays associativos. Isso preserva a ordem de inserção e mantém
compatibilidade com o Bash 3.2 distribuído por padrão no macOS.

## Tratamento de erros

O script principal usa `set -Eeuo pipefail` com um `trap ERR` que encerra com
código `3`. Como o objetivo é tolerância a falhas parciais (um módulo pode
falhar sem abortar a auditoria), cada chamada de módulo é guardada com
`|| utils::warn`, e as auditorias por alvo são guardadas com `|| rc=$?`.

## Cache

O cache fica em `WEBAUDIT_CACHE_DIR` (padrão `cache/`), particionado por
namespace (`dns`, `versions`, `cve`, ...). Cada entrada armazena o timestamp
de expiração na primeira linha; leituras vencidas são descartadas.
