#!/usr/bin/env bash
#
# cli.sh - Parsing de argumentos e ajuda do WebAudit.
#
# Responsabilidade única: interpretar a linha de comando, popular variáveis
# de configuração globais (WEBAUDIT_*) e imprimir help/version.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_CLI_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_CLI_LOADED=1

WEBAUDIT_VERSION="1.1.0"

# Valores padrão (podem ser sobrescritos por config.conf e depois por flags).
: "${WEBAUDIT_TIMEOUT:=10}"
: "${WEBAUDIT_USER_AGENT:=WebAudit/${WEBAUDIT_VERSION}}"
: "${WEBAUDIT_PORT_HTTP:=80}"
: "${WEBAUDIT_PORT_HTTPS:=443}"
: "${WEBAUDIT_OUTPUT:=text}"       # text|json|csv|html|markdown|yaml
: "${WEBAUDIT_VERBOSE:=0}"
: "${WEBAUDIT_QUIET:=0}"
: "${WEBAUDIT_CACHE_ENABLED:=1}"
: "${WEBAUDIT_CVE_ENABLED:=1}"
: "${WEBAUDIT_CVE_MAX:=500}"      # teto de CVEs listadas (0 = ilimitado)
: "${WEBAUDIT_NVD_PAGE:=2000}"    # resultsPerPage da NVD (máx. permitido)
: "${WEBAUDIT_LOG_FILE:=}"
: "${WEBAUDIT_PROXY:=}"

# Lista de hosts alvo e arquivo de scan.
declare -a WEBAUDIT_TARGETS=()
WEBAUDIT_HOSTFILE=""

cli::version() {
  printf 'WebAudit %s\n' "${WEBAUDIT_VERSION}"
}

cli::usage() {
  cat <<'EOF'
WebAudit - Ferramenta de auditoria de servidores Web (HTTP/HTTPS/TLS)

USO:
  webaudit.sh [OPÇÕES] <host|url> [host2 ...]
  webaudit.sh [OPÇÕES] <arquivo_de_hosts.txt>

OPÇÕES:
  -o, --output FORMATO   Formato de saída: text (padrão), json, csv, html,
                         markdown, yaml
      --json             Atalho para --output json
      --csv              Atalho para --output csv
      --html             Atalho para --output html
      --markdown         Atalho para --output markdown
      --yaml             Atalho para --output yaml

  -p, --port-http N      Porta HTTP (padrão: 80)
  -P, --port-https N     Porta HTTPS (padrão: 443)
  -t, --timeout SEG      Timeout por operação (padrão: 10)
  -A, --user-agent STR   User-Agent das requisições

      --proxy URL        Proxy para HTTP/HTTPS (curl -x)
      --no-cache         Desabilita cache local
      --no-cve           Desabilita consulta de CVEs
      --cve-max N        Máximo de CVEs listadas (0 = todas; padrão: 500)
      --nvd-key KEY      API key para a NVD (NIST)
      --github-token TOK Token para GitHub Security Advisories

      --log ARQUIVO      Grava log estruturado no arquivo
  -c, --config ARQUIVO   Caminho para config.conf

  -v, --verbose          Modo detalhado (todos os detalhes)
  -q, --quiet            Modo silencioso (apenas OK/WARNING/CRITICAL)
      --no-color         Desabilita cores ANSI

  -h, --help             Mostra esta ajuda
  -V, --version          Mostra a versão

EXIT CODES:
  0 = OK        1 = WARNING       2 = CRITICAL      3 = INTERNAL ERROR

EXEMPLOS:
  webaudit.sh exemplo.com
  webaudit.sh --json https://exemplo.com > relatorio.json
  webaudit.sh --html hosts.txt > relatorio.html
  webaudit.sh -v -t 15 exemplo.com:8443
EOF
}

# cli::parse "$@" - interpreta argumentos.
# Vários globais atribuídos aqui são lidos em módulos separados
# (cve.sh, colors.sh, webaudit.sh); ShellCheck não enxerga o uso cruzado.
# shellcheck disable=SC2034
cli::parse() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output)     WEBAUDIT_OUTPUT="$2"; shift 2 ;;
      --json)          WEBAUDIT_OUTPUT="json"; shift ;;
      --csv)           WEBAUDIT_OUTPUT="csv"; shift ;;
      --html)          WEBAUDIT_OUTPUT="html"; shift ;;
      --markdown)      WEBAUDIT_OUTPUT="markdown"; shift ;;
      --yaml)          WEBAUDIT_OUTPUT="yaml"; shift ;;
      -p|--port-http)  WEBAUDIT_PORT_HTTP="$2"; shift 2 ;;
      -P|--port-https) WEBAUDIT_PORT_HTTPS="$2"; shift 2 ;;
      -t|--timeout)    WEBAUDIT_TIMEOUT="$2"; shift 2 ;;
      -A|--user-agent) WEBAUDIT_USER_AGENT="$2"; shift 2 ;;
      --proxy)         WEBAUDIT_PROXY="$2"; shift 2 ;;
      --no-cache)      WEBAUDIT_CACHE_ENABLED=0; shift ;;
      --no-cve)        WEBAUDIT_CVE_ENABLED=0; shift ;;
      --cve-max)       WEBAUDIT_CVE_MAX="$2"; shift 2 ;;
      --nvd-key)       WEBAUDIT_NVD_API_KEY="$2"; shift 2 ;;
      --github-token)  WEBAUDIT_GITHUB_TOKEN="$2"; shift 2 ;;
      --log)           WEBAUDIT_LOG_FILE="$2"; shift 2 ;;
      -c|--config)     WEBAUDIT_CONFIG_FILE="$2"; shift 2 ;;
      -v|--verbose)    WEBAUDIT_VERBOSE=1; shift ;;
      -q|--quiet)      WEBAUDIT_QUIET=1; shift ;;
      --no-color)      WEBAUDIT_NO_COLOR=1; colors::init; shift ;;
      -h|--help)       cli::usage; exit 0 ;;
      -V|--version)    cli::version; exit 0 ;;
      --)              shift; while [[ $# -gt 0 ]]; do WEBAUDIT_TARGETS+=("$1"); shift; done ;;
      -*)              utils::die "Opção desconhecida: $1 (use --help)" ;;
      *)
        # Se for arquivo existente, trata como lista de hosts.
        if [[ -f "$1" && -z "${WEBAUDIT_HOSTFILE}" && ${#WEBAUDIT_TARGETS[@]} -eq 0 ]]; then
          WEBAUDIT_HOSTFILE="$1"
        else
          WEBAUDIT_TARGETS+=("$1")
        fi
        shift
        ;;
    esac
  done

  export WEBAUDIT_OUTPUT WEBAUDIT_PORT_HTTP WEBAUDIT_PORT_HTTPS WEBAUDIT_TIMEOUT
  export WEBAUDIT_USER_AGENT WEBAUDIT_PROXY WEBAUDIT_CACHE_ENABLED WEBAUDIT_CVE_ENABLED
  export WEBAUDIT_CVE_MAX WEBAUDIT_NVD_PAGE
  export WEBAUDIT_VERBOSE WEBAUDIT_QUIET WEBAUDIT_LOG_FILE
}

# cli::validate - checa consistência da configuração parseada.
cli::validate() {
  case "${WEBAUDIT_OUTPUT}" in
    text|json|csv|html|markdown|yaml) ;;
    *) utils::die "Formato de saída inválido: ${WEBAUDIT_OUTPUT}" ;;
  esac
  [[ "${WEBAUDIT_TIMEOUT}" =~ ^[0-9]+$ ]] || utils::die "Timeout inválido: ${WEBAUDIT_TIMEOUT}"
  [[ "${WEBAUDIT_CVE_MAX}" =~ ^[0-9]+$ ]] || utils::die "Valor inválido para --cve-max: ${WEBAUDIT_CVE_MAX}"

  if [[ -z "${WEBAUDIT_HOSTFILE}" && ${#WEBAUDIT_TARGETS[@]} -eq 0 ]]; then
    cli::usage
    exit 3
  fi
}
