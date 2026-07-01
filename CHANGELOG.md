# Changelog

Todas as mudanças relevantes do WebAudit são documentadas neste arquivo.

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/)
e o projeto adota [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado
- Correlação de CVE por CPE (`virtualMatchString` da NVD 2.0), muito mais
  precisa que a busca por palavra-chave, com fallback automático para keyword
  quando não há mapeamento de CPE.
- Paginação completa da NVD (`startIndex`/`resultsPerPage=2000` até
  `totalResults`), respeitando o rate limit oficial: ~6s entre requisições
  sem chave e ~0,6s com `--nvd-key`.
- Flag `--cve-max N` (padrão 500; `0` = todas) para controlar o teto de CVEs.
- Lista de CVEs sempre exibida no relatório em texto (não só em modo verbose).
- Campo `cve_details` na saída `--json`: objeto completo por CVE com CVSS
  (versão, score, severidade, vetor), CWE, descrição integral, referências,
  status KEV e **versões afetadas** (faixas versionStart/End).

### Corrigido
- Mapeamento de CPE do nginx atualizado para `f5:nginx` (vendor atual na NVD).
- Contagem de CVEs agora reflete o total real (`totalResults`), não o teto.

## [1.0.0] - 2026-07-01

### Adicionado
- Auditoria completa de servidores web em Bash puro (dependências mínimas:
  `bash`, `curl`, `openssl`).
- Módulos de coleta: DNS, TCP, HTTP, HTTPS, TLS, certificado, cabeçalhos,
  cabeçalhos de segurança, identificação de servidor/SO, fingerprint,
  comparação de versão e consulta de CVEs.
- Detecção de versões TLS (1.0/1.1/1.2/1.3), cipher negociado, ALPN,
  forward secrecy, compressão, session ticket, reuso de sessão e OCSP
  stapling / Must-Staple.
- Análise de certificado: emissor, SAN, wildcard, validade, algoritmo de
  chave e assinatura, verificação de hostname e cadeia.
- Pontuação de cabeçalhos de segurança (HSTS, CSP, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Permissions-Policy, COEP/COOP/CORP).
- Comparação de versão via API [endoflife.date](https://endoflife.date).
- Consulta de vulnerabilidades via [NVD 2.0](https://nvd.nist.gov) e
  [OSV.dev](https://osv.dev), com cache local e suporte a chave de API do NVD.
- Formatos de saída: texto (padrão), `--json`, `--csv`, `--html`,
  `--markdown` e `--yaml`.
- Modo scanner para auditar vários hosts a partir de um arquivo.
- Cache local com TTL por categoria de consulta.
- Códigos de saída semânticos: `0` OK, `1` WARNING, `2` CRITICAL,
  `3` erro interno.
- Suporte a Linux e macOS (detecção de plataforma e comandos portáveis).
- Suíte de testes (`tests/run_tests.sh`) e integração contínua com
  ShellCheck e execução dos testes.

[Não lançado]: https://github.com/SEU_USUARIO/webaudit/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/SEU_USUARIO/webaudit/releases/tag/v1.0.0
