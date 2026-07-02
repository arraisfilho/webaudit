#!/usr/bin/env bash
#
# utils.sh - Utilitários centrais do WebAudit.
#
# Responsabilidades:
#   - Detecção de sistema operacional (Linux/macOS/BSD).
#   - Wrappers portáveis para comandos que divergem entre GNU e BSD
#     (date, timeout, sed, stat, mktemp, base64).
#   - Sistema de logging (stderr + arquivo opcional).
#   - Cache local em disco com TTL.
#   - "Result store": armazenamento chave->valor dos achados da auditoria,
#     consumido pelos módulos de saída (report/json/csv/html/markdown).
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_UTILS_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_UTILS_LOADED=1

# Bash 5.2 ativa 'patsub_replacement' por padrão: nesse modo, um '&' na
# string de substituição de ${var//pat/rep} é trocado pelo texto casado.
# Isso quebra os escapes HTML/JSON (ex.: &lt; viraria <lt;). Desativamos
# globalmente; versões de bash sem essa opção simplesmente ignoram.
shopt -u patsub_replacement 2>/dev/null || true

# ---------------------------------------------------------------------------
# Detecção de plataforma
# ---------------------------------------------------------------------------

# WEBAUDIT_OS: linux | macos | bsd | unknown
utils::detect_os() {
  local uname_s
  uname_s="$(uname -s 2>/dev/null || echo unknown)"
  case "${uname_s}" in
    Linux)   WEBAUDIT_OS="linux" ;;
    Darwin)  WEBAUDIT_OS="macos" ;;
    *BSD)    WEBAUDIT_OS="bsd" ;;
    *)       WEBAUDIT_OS="unknown" ;;
  esac
  export WEBAUDIT_OS
}

# utils::has <comando> - verifica se um binário existe no PATH.
utils::has() {
  command -v "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Wrappers portáveis
# ---------------------------------------------------------------------------

# utils::epoch <data_string> - converte uma data (formato do openssl/GMT)
# para epoch. Trata diferenças entre GNU date (-d) e BSD date (-j -f).
# Se a conversão falhar, retorna string vazia.
utils::epoch() {
  local input="$1"
  local out=""
  if [[ "${WEBAUDIT_OS}" == "linux" ]]; then
    out="$(date -u -d "${input}" +%s 2>/dev/null || true)"
  else
    # BSD/macOS: tenta formato do openssl "Mon DD HH:MM:SS YYYY GMT"
    out="$(date -j -u -f "%b %e %T %Y %Z" "${input}" +%s 2>/dev/null || true)"
    if [[ -z "${out}" ]]; then
      out="$(date -j -u -f "%Y-%m-%d %H:%M:%S" "${input}" +%s 2>/dev/null || true)"
    fi
  fi
  printf '%s' "${out}"
}

# utils::now_epoch - epoch atual (UTC).
utils::now_epoch() { date -u +%s; }

# utils::now_iso - timestamp ISO-8601 UTC.
utils::now_iso() {
  if [[ "${WEBAUDIT_OS}" == "linux" ]]; then
    date -u +"%Y-%m-%dT%H:%M:%SZ"
  else
    date -u +"%Y-%m-%dT%H:%M:%SZ"
  fi
}

# utils::run_timeout <segundos> <cmd...> - executa comando com limite de tempo.
# Usa timeout/gtimeout se disponível; caso contrário executa sem limite.
utils::run_timeout() {
  local secs="$1"; shift
  if utils::has timeout; then
    timeout "${secs}" "$@"
  elif utils::has gtimeout; then
    gtimeout "${secs}" "$@"
  else
    "$@"
  fi
}

# utils::mktemp_file - cria arquivo temporário portável.
utils::mktemp_file() {
  mktemp "${TMPDIR:-/tmp}/webaudit.XXXXXX"
}

# utils::mktemp_dir - cria diretório temporário portável.
utils::mktemp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/webaudit.XXXXXX"
}

# utils::b64 - base64 encode de stdin (uma linha, sem quebras).
utils::b64() {
  if [[ "${WEBAUDIT_OS}" == "macos" || "${WEBAUDIT_OS}" == "bsd" ]]; then
    base64 | tr -d '\n'
  else
    base64 -w0 2>/dev/null || base64 | tr -d '\n'
  fi
}

# ---------------------------------------------------------------------------
# Manipulação de strings
# ---------------------------------------------------------------------------

# utils::trim - remove espaços em branco no início/fim (stdin).
utils::trim() {
  local s
  s="$(cat)"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "${s}"
}

# utils::lower - minúsculas (stdin).
utils::lower() { tr '[:upper:]' '[:lower:]'; }

# utils::json_escape <str> - escapa string para uso seguro em JSON.
utils::json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\n'/\\n}"
  printf '%s' "${s}"
}

# utils::html_escape <str> - escapa string para HTML.
utils::html_escape() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  s="${s//\"/&quot;}"
  printf '%s' "${s}"
}

# utils::csv_escape <str> - escapa string para CSV (RFC 4180).
utils::csv_escape() {
  local s="$1"
  if [[ "${s}" == *","* || "${s}" == *"\""* || "${s}" == *$'\n'* ]]; then
    s="${s//\"/\"\"}"
    printf '"%s"' "${s}"
  else
    printf '%s' "${s}"
  fi
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# Níveis: DEBUG < INFO < WARN < ERROR. Verbose habilita DEBUG.
# WEBAUDIT_LOG_FILE (opcional) recebe as mensagens estruturadas.

utils::log() {
  local level="$1"; shift
  local msg="$*"
  local ts; ts="$(utils::now_iso)"

  # Filtro por verbosidade em stderr.
  case "${level}" in
    DEBUG) [[ "${WEBAUDIT_VERBOSE:-0}" == "1" ]] || { _utils::log_file "${ts}" "${level}" "${msg}"; return 0; } ;;
  esac

  local color=""
  case "${level}" in
    DEBUG) color="${C_GRAY:-}" ;;
    INFO)  color="${C_BLUE:-}" ;;
    WARN)  color="${C_YELLOW:-}" ;;
    ERROR) color="${C_RED:-}" ;;
  esac

  if [[ "${WEBAUDIT_QUIET:-0}" != "1" || "${level}" == "ERROR" ]]; then
    printf '%b[%s]%b %s\n' "${color}" "${level}" "${C_RESET:-}" "${msg}" >&2
  fi
  _utils::log_file "${ts}" "${level}" "${msg}"
}

_utils::log_file() {
  local ts="$1" level="$2" msg="$3"
  [[ -n "${WEBAUDIT_LOG_FILE:-}" ]] || return 0
  printf '%s\t%s\t%s\t%s\n' "${ts}" "${level}" "${WEBAUDIT_CURRENT_HOST:-}" "${msg}" \
    >>"${WEBAUDIT_LOG_FILE}" 2>/dev/null || true
}

utils::debug() { utils::log DEBUG "$@"; }
utils::info()  { utils::log INFO  "$@"; }
utils::warn()  { utils::log WARN  "$@"; }
utils::error() { utils::log ERROR "$@"; }

# utils::die <msg> - loga erro e encerra com exit code INTERNAL ERROR (3).
utils::die() {
  utils::error "$@"
  exit 3
}

# ---------------------------------------------------------------------------
# Cache local (TTL em segundos)
# ---------------------------------------------------------------------------
# Estrutura: ${WEBAUDIT_CACHE_DIR}/<namespace>/<hash>.cache
# Primeira linha = epoch de expiração; restante = payload.

utils::cache_key() {
  # Gera chave estável a partir dos argumentos.
  printf '%s' "$*" | openssl dgst -sha256 2>/dev/null | awk '{print $NF}'
}

utils::cache_get() {
  local ns="$1" key="$2"
  [[ "${WEBAUDIT_CACHE_ENABLED:-1}" == "1" ]] || return 1
  local file
  file="${WEBAUDIT_CACHE_DIR}/${ns}/$(utils::cache_key "${key}").cache"
  [[ -f "${file}" ]] || return 1
  local exp; exp="$(head -n1 "${file}" 2>/dev/null)"
  [[ "${exp}" =~ ^[0-9]+$ ]] || return 1
  if (( exp < $(utils::now_epoch) )); then
    rm -f "${file}" 2>/dev/null || true
    return 1
  fi
  tail -n +2 "${file}"
  return 0
}

utils::cache_set() {
  local ns="$1" key="$2" ttl="$3" payload="$4"
  [[ "${WEBAUDIT_CACHE_ENABLED:-1}" == "1" ]] || return 0
  local dir="${WEBAUDIT_CACHE_DIR}/${ns}"
  mkdir -p "${dir}" 2>/dev/null || return 0
  local file
  file="${dir}/$(utils::cache_key "${key}").cache"
  {
    printf '%s\n' "$(( $(utils::now_epoch) + ttl ))"
    printf '%s' "${payload}"
  } >"${file}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Result store (chave -> valor)
# ---------------------------------------------------------------------------
# Guarda os achados de forma ordenada para os módulos de saída.
# Implementado com arrays indexados para funcionar no Bash 3.2 do macOS.

declare -a WEBAUDIT_RESULT_ORDER=()
declare -a WEBAUDIT_RESULT_VALUES=()

utils::result_reset() {
  WEBAUDIT_RESULT_ORDER=()
  WEBAUDIT_RESULT_VALUES=()
}

# utils::_result_index <chave> - imprime o índice da chave no store.
utils::_result_index() {
  local key="$1" i
  for (( i=0; i<${#WEBAUDIT_RESULT_ORDER[@]}; i++ )); do
    if [[ "${WEBAUDIT_RESULT_ORDER[$i]}" == "${key}" ]]; then
      printf '%s' "${i}"
      return 0
    fi
  done
  return 1
}

# utils::result_set <chave> <valor>
utils::result_set() {
  local key="$1"; shift
  local val="$*" idx
  if idx="$(utils::_result_index "${key}")"; then
    WEBAUDIT_RESULT_VALUES[idx]="${val}"
  else
    WEBAUDIT_RESULT_ORDER+=("${key}")
    WEBAUDIT_RESULT_VALUES+=("${val}")
  fi
}

# utils::result_get <chave> - imprime valor (ou vazio).
utils::result_get() {
  local idx
  if idx="$(utils::_result_index "$1")"; then
    printf '%s' "${WEBAUDIT_RESULT_VALUES[$idx]}"
  fi
}

# utils::result_has <chave> - retorna 0 se existe e não é vazio.
utils::result_has() {
  local idx
  idx="$(utils::_result_index "$1")" || return 1
  [[ -n "${WEBAUDIT_RESULT_VALUES[$idx]}" ]]
}
