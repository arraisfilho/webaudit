#!/usr/bin/env bash
#
# webaudit.sh - Ponto de entrada do WebAudit.
#
# Ferramenta modular de auditoria de servidores Web (HTTP/HTTPS/TLS) escrita
# em Bash puro. Orquestra os módulos em lib/, executa a auditoria de um ou
# vários hosts e emite o relatório no formato escolhido.
#
# Exit codes: 0=OK 1=WARNING 2=CRITICAL 3=INTERNAL ERROR
#
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Resolução de caminhos e carregamento dos módulos
# ---------------------------------------------------------------------------
WEBAUDIT_HOME="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
WEBAUDIT_LIB="${WEBAUDIT_HOME}/lib"
WEBAUDIT_CACHE_DIR="${WEBAUDIT_CACHE_DIR:-${WEBAUDIT_HOME}/cache}"
export WEBAUDIT_HOME WEBAUDIT_LIB WEBAUDIT_CACHE_DIR

# A ordem importa: colors/utils/cli primeiro; depois os coletores; por fim as
# saídas. Cada módulo é idempotente (guard de load).
# shellcheck source=lib/colors.sh
source "${WEBAUDIT_LIB}/colors.sh"
# shellcheck source=lib/utils.sh
source "${WEBAUDIT_LIB}/utils.sh"

utils::detect_os

# shellcheck source=lib/cli.sh
source "${WEBAUDIT_LIB}/cli.sh"

# Carrega config.conf (se existir) ANTES de aplicar as flags, para que a linha
# de comando tenha precedência.
webaudit::load_config() {
  local cfg="${WEBAUDIT_CONFIG_FILE:-${WEBAUDIT_HOME}/config.conf}"
  if [[ -f "${cfg}" ]]; then
    utils::debug "Carregando config: ${cfg}"
    # shellcheck source=/dev/null
    source "${cfg}"
  fi
}

for _m in dns tcp http tls cert headers security server fingerprint \
          versions cve report json csv html markdown; do
  # shellcheck source=/dev/null
  source "${WEBAUDIT_LIB}/${_m}.sh"
done
unset _m

# ---------------------------------------------------------------------------
# Tratamento de erros
# ---------------------------------------------------------------------------
webaudit::on_error() {
  local code=$? line=${1:-?}
  utils::error "Erro interno na linha ${line} (exit ${code})"
  exit 3
}
trap 'webaudit::on_error "${LINENO}"' ERR

webaudit::cleanup() {
  # Remove temporários porventura criados.
  [[ -n "${WEBAUDIT_TMPDIR:-}" && -d "${WEBAUDIT_TMPDIR}" ]] && rm -rf "${WEBAUDIT_TMPDIR}" 2>/dev/null || true
}
trap webaudit::cleanup EXIT

# ---------------------------------------------------------------------------
# Normalização de alvo (aceita url ou host[:porta])
# ---------------------------------------------------------------------------
# Ecoa "host porta_https" e ajusta WEBAUDIT_PORT_* quando a URL traz porta.
webaudit::normalize_target() {
  local raw="$1"
  local host="${raw}"
  local port="${WEBAUDIT_PORT_HTTPS}"
  # Remove esquema.
  host="${host#http://}"
  host="${host#https://}"
  # Remove caminho/query.
  host="${host%%/*}"
  # Porta explícita? (ignora IPv6 literal como [::1])
  if [[ "${host}" == *:* && "${host}" != *]:* ]]; then
    local p="${host##*:}"
    host="${host%%:*}"
    if [[ "${p}" =~ ^[0-9]+$ ]]; then
      port="${p}"
    fi
  fi
  # Emite "host porta" para o chamador consumir sem depender de subshell.
  printf '%s %s' "${host}" "${port}"
}

# ---------------------------------------------------------------------------
# Auditoria de um host
# ---------------------------------------------------------------------------
webaudit::audit_one() {
  local target="$1"
  local host port
  IFS=$' \t' read -r host port < <(webaudit::normalize_target "${target}")
  WEBAUDIT_PORT_HTTPS="${port:-${WEBAUDIT_PORT_HTTPS}}"
  WEBAUDIT_CURRENT_HOST="${host}"
  export WEBAUDIT_CURRENT_HOST WEBAUDIT_PORT_HTTPS

  utils::result_reset

  local t0 t1 elapsed
  t0="$(date +%s)"

  utils::info "Auditando ${host}"

  # Pipeline de coleta. Cada módulo é tolerante a falhas parciais.
  dns::run         "${host}" || utils::warn "Falha no modulo dns"
  tcp::run         "${host}" || utils::warn "Falha no modulo tcp"
  http::run        "${host}" || utils::warn "Falha no modulo http"
  headers::run     "${host}" || utils::warn "Falha no modulo headers"
  tls::run         "${host}" || utils::warn "Falha no modulo tls"
  cert::run        "${host}" || utils::warn "Falha no modulo cert"
  security::run    "${host}" || utils::warn "Falha no modulo security"
  server::run      "${host}" || utils::warn "Falha no modulo server"
  fingerprint::run "${host}" || utils::warn "Falha no modulo fingerprint"
  versions::run    "${host}" || utils::warn "Falha no modulo versions"
  cve::run         "${host}" || utils::warn "Falha no modulo cve"

  t1="$(date +%s)"
  # Tempo com 2 casas (usa awk se disponível).
  if utils::has awk; then
    elapsed="$(awk -v a="${t0}" -v b="${t1}" 'BEGIN{printf "%.2f", b-a}')"
  else
    elapsed="$(( t1 - t0 ))"
  fi

  report::emit "${host}" "${elapsed}"

  # Log resumido.
  utils::log INFO "Concluido ${host} -> $(report::overall) em ${elapsed}s"

  local _sc
  _sc="$(report::status_code)"
  return "${_sc}"
}

# ---------------------------------------------------------------------------
# Modo scanner (arquivo de hosts) com agregação por formato
# ---------------------------------------------------------------------------
webaudit::scan_file() {
  local file="$1"
  local -a hosts=()
  local line
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="$(printf '%s' "${line}" | utils::trim)"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    hosts+=("${line}")
  done <"${file}"

  [[ ${#hosts[@]} -gt 0 ]] || utils::die "Nenhum host valido em ${file}"

  local worst=0 rc h first=1

  case "${WEBAUDIT_OUTPUT}" in
    json)  printf '[\n' ;;
    csv)   csv::header ;;
    html)  html::doc_header ;;
    yaml)  : ;;  # lista YAML já usa "- " por item
  esac

  for h in "${hosts[@]}"; do
    if [[ "${WEBAUDIT_OUTPUT}" == "json" ]]; then
      [[ ${first} -eq 1 ]] && first=0 || printf ',\n'
    fi
    rc=0
    webaudit::audit_one "${h}" || rc=$?
    if (( rc > worst )); then worst=${rc}; fi
    [[ "${WEBAUDIT_OUTPUT}" == "text" ]] && printf '\n'
  done

  case "${WEBAUDIT_OUTPUT}" in
    json) printf '\n]\n' ;;
    html) html::doc_footer ;;
  esac

  return "${worst}"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  # 1) Config primeiro (pré-parse mínimo para -c/--config).
  local i
  for (( i=1; i<=$#; i++ )); do
    if [[ "${!i}" == "-c" || "${!i}" == "--config" ]]; then
      local j=$((i+1)); WEBAUDIT_CONFIG_FILE="${!j:-}"
    fi
  done
  webaudit::load_config

  # 2) Flags (precedência sobre config).
  cli::parse "$@"
  cli::validate

  # 3) Preparação de cache/log.
  mkdir -p "${WEBAUDIT_CACHE_DIR}" 2>/dev/null || true
  if [[ -n "${WEBAUDIT_LOG_FILE}" ]]; then
    : >>"${WEBAUDIT_LOG_FILE}" 2>/dev/null || utils::warn "Nao foi possivel abrir log: ${WEBAUDIT_LOG_FILE}"
  fi

  local rc=0
  if [[ -n "${WEBAUDIT_HOSTFILE}" ]]; then
    rc=0
    webaudit::scan_file "${WEBAUDIT_HOSTFILE}" || rc=$?
  else
    # Um ou mais alvos na linha de comando.
    local worst=0 t
    local first=1
    case "${WEBAUDIT_OUTPUT}" in
      json)  [[ ${#WEBAUDIT_TARGETS[@]} -gt 1 ]] && printf '[\n' ;;
      csv)   csv::header ;;
      html)  html::doc_header ;;
    esac
    for t in "${WEBAUDIT_TARGETS[@]}"; do
      if [[ "${WEBAUDIT_OUTPUT}" == "json" && ${#WEBAUDIT_TARGETS[@]} -gt 1 ]]; then
        [[ ${first} -eq 1 ]] && first=0 || printf ',\n'
      fi
      local r=0
      webaudit::audit_one "${t}" || r=$?
      if (( r > worst )); then worst=${r}; fi
      [[ "${WEBAUDIT_OUTPUT}" == "text" && ${#WEBAUDIT_TARGETS[@]} -gt 1 ]] && printf '\n'
    done
    case "${WEBAUDIT_OUTPUT}" in
      json)  [[ ${#WEBAUDIT_TARGETS[@]} -gt 1 ]] && printf '\n]\n' ;;
      html)  html::doc_footer ;;
    esac
    rc=${worst}
  fi

  exit "${rc}"
}

main "$@"
