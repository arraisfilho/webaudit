# Formatos de saída

O WebAudit produz o mesmo conjunto de resultados em diferentes formatos,
selecionados por flag. O formato padrão é texto para terminal.

## Texto (padrão)

Relatório legível para terminal, com rótulos alinhados e cores (desativáveis
com `--no-color` ou `NO_COLOR=1`). O modo `-q/--quiet` reduz a saída a uma
linha por host (`NOTA host`). O modo `-v/--verbose` inclui todos os campos
coletados e a lista completa de CVEs.

## `--json`

Objeto JSON por host com as chaves `host`, `elapsed_seconds`, `overall` e
`results` (mapa `modulo.campo` → valor). No modo scanner, a saída é um array
de objetos. É o formato recomendado para integração com outras ferramentas.

```json
{
  "host": "example.com",
  "elapsed_seconds": "2.00",
  "overall": "WARNING",
  "results": { "dns.ipv4": "...", "tls.negotiated": "TLSv1.3", "...": "..." }
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
