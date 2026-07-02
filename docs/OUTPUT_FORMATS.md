# Formatos de saída

O WebAudit produz o mesmo conjunto de resultados em diferentes formatos,
selecionados por flag. O formato padrão é texto para terminal.

## Texto (padrão)

Relatório legível para terminal, organizado por seções, com rótulos alinhados,
valores ausentes normalizados como `-`, status coloridos e CVEs em tabela
compacta. As cores podem ser desativadas com `--no-color` ou `NO_COLOR=1`.
O modo `-q/--quiet` reduz a saída a uma linha por host (`NOTA host`). O modo
`-v/--verbose` inclui todos os campos coletados.

## `--json`

Objeto JSON por host com as chaves `host`, `elapsed_seconds`, `overall`,
`results` (mapa `modulo.campo` → valor) e `cve_details`. No modo scanner, a
saída é um array de objetos. É o formato recomendado para integração com
outras ferramentas.

O campo `cve_details` traz um array com o objeto completo de cada CVE:
`id`, `published`, `lastModified`, `status`, `cvss` (version/score/severity/
vector), `cwe`, `description`, `affected` (faixas de versão afetadas), `kev`,
`references` e `url`. É a fonte com o máximo de detalhe.

```json
{
  "host": "example.com",
  "elapsed_seconds": "2.00",
  "overall": "WARNING",
  "results": { "tls.negotiated": "TLSv1.3", "...": "..." },
  "cve_details": [ { "id": "CVE-2021-23017", "cvss": { "score": 7.7, "severity": "HIGH" }, "affected": [ ... ] } ]
}
```

## `--csv`

Uma linha por host com um cabeçalho fixo de colunas selecionadas (as mais
usadas para planilha/relatório). Campos com vírgula, aspas ou quebra de linha
são escapados conforme a RFC 4180.

## `--yaml`

Lista YAML (um item `- host:` por alvo) com o mesmo conteúdo do JSON. Útil
para versionar resultados ou alimentar pipelines que consomem YAML.

## `--markdown`

Seções por host com tabelas (Rede, TLS e Certificado, Servidor, Segurança,
Vulnerabilidades). Adequado para colar em issues, wikis ou relatórios.

## `--html`

Documento HTML autocontido (CSS embutido, sem dependências externas) com um
cartão por host, selo de status (OK/WARNING/CRITICAL) e tabela de CVEs.

## Códigos de saída

O código de saída reflete a pior nota entre os hosts auditados:

| Código | Significado   |
|--------|---------------|
| 0      | OK            |
| 1      | WARNING       |
| 2      | CRITICAL      |
| 3      | Erro interno  |

Isso permite usar o WebAudit em pipelines: `webaudit exemplo.com || tratar_falha`.
