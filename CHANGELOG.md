# Changelog

Todas as mudanças relevantes do WebAudit são documentadas neste arquivo.

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/)
e o projeto adota [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [1.1.0] - 2026-07-02

### Adicionado
- Checagem de dependências ao iniciar uma auditoria, com erro claro para
  dependências obrigatórias ausentes e sugestões de instalação para macOS e
  Linux.
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
- Workflow de CI para GitHub Actions, templates de issue e template de pull
  request.

### Alterado
- Relatório em texto reorganizado em seções, com rótulos alinhados, valores
  ausentes como `-` e tabela compacta para CVEs.
- Result store interno refatorado para arrays indexados paralelos, preservando
  a ordem de inserção sem exigir arrays associativos.
- A lista de CVEs em texto passa a omitir a descrição (que poluía o terminal);
  a descrição completa continua disponível em `cve_details` no `--json`.
- A consulta NVD reduz `resultsPerPage` ao valor de `--cve-max` quando o teto
  é menor que o máximo da API, diminuindo timeouts em produtos com muitas CVEs.
- Alvos informados como IP literal passam a ser tratados como DNS resolvido,
  preservando o IP em `dns.ipv4`/`dns.ipv6`.

### Corrigido
- Compatibilidade com o Bash 3.2 padrão do macOS: removido uso de `declare -g`,
  arrays associativos e namerefs (`local -n`).
- Saída JSON com `jq` agora segue o contrato documentado, mantendo achados em
  `results` em vez de expor chaves `modulo.campo` no topo do objeto.
- `trap ERR` deixa de registrar como erro interno falhas esperadas em
  command substitutions usadas como sondagens.
- Teste TCP passa a usar fallback com `nc`, evitando falso `CRITICAL` quando
  `/dev/tcp` não está disponível no Bash do sistema.
- Mapeamento de CPE do nginx atualizado para `f5:nginx` (vendor atual na NVD).
- Contagem de CVEs agora reflete o total real (`totalResults`), não o teto.
- Respostas vazias ou inválidas da NVD deixam de ser tratadas como
  "Nenhuma conhecida"; agora são sinalizadas como consulta indisponível.
- Consulta de CVE sem `--nvd-key` não dispara mais erro de array vazio no
  Bash 3.2 com `set -u`.
- Tempo final passa a ser formatado com locale `C`, mantendo ponto decimal em
  logs e relatórios.
- `versions::_cmp` deixa de retornar `-1` (interpretado como opção por
  `printf` em alguns shells), passando a usar `lt`/`eq`/`gt`. Corrige o erro
  "printf: -1: invalid option" e o campo Status vazio na comparação de versão.

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

[1.1.0]: https://github.com/arraisfilho/webaudit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/arraisfilho/webaudit/releases/tag/v1.0.0
