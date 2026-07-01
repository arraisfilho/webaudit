#!/usr/bin/env bash
#
# run_tests.sh - Suíte de testes do WebAudit.
#
# Não depende de rede para os testes unitários (funções puras de lib/).
# Um bloco opcional de testes de integração roda somente quando a variável
# WEBAUDIT_TEST_NET=1 está definida (evita flakiness em CI sem egresso).
#
# Uso:
#   bash tests/run_tests.sh
#   WEBAUDIT_TEST_NET=1 bash tests/run_tests.sh
#
# shellcheck shell=bash

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
LIB="${ROOT}/lib"

PASS=0
FAIL=0
FAILED_NAMES=()

# ---------------------------------------------------------------------------
# Infra mínima de asserção
# ---------------------------------------------------------------------------
_ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
_no()   { FAIL=$((FAIL+1)); FAILED_NAMES+=("$1"); printf '  \033[31mFALHA\033[0m %s\n' "$1"; }

assert_eq() { # <esperado> <obtido> <nome>
  if [[ "$1" == "$2" ]]; then _ok "$3"; else _no "$3 (esperado='$1' obtido='$2')"; fi
}
assert_contains() { # <agulha> <palheiro> <nome>
  if [[ "$2" == *"$1"* ]]; then _ok "$3"; else _no "$3 (nao contem '$1')"; fi
}
assert_rc() { # <esperado_rc> <nome> ; usa $? do comando anterior via wrapper
  local exp="$1" got="$2" name="$3"
  if [[ "${exp}" == "${got}" ]]; then _ok "${name}"; else _no "${name} (rc esperado=${exp} obtido=${got})"; fi
}

section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
# Carrega as libs necessárias (colors/utils primeiro).
# ---------------------------------------------------------------------------
# Ambiente controlado para os testes.
export WEBAUDIT_NO_COLOR=1
export WEBAUDIT_QUIET=1
WEBAUDIT_CACHE_DIR="$(mktemp -d)"
export WEBAUDIT_CACHE_DIR
trap 'rm -rf "${WEBAUDIT_CACHE_DIR}" 2>/dev/null || true' EXIT

# shellcheck source=/dev/null
source "${LIB}/colors.sh"
# shellcheck source=/dev/null
source "${LIB}/utils.sh"

# ---------------------------------------------------------------------------
section "utils::trim / lower"
# ---------------------------------------------------------------------------
assert_eq "abc" "$(printf '  abc  ' | utils::trim)" "trim remove espacos"
assert_eq "abc" "$(printf 'ABC' | utils::lower)" "lower minusculiza"

# ---------------------------------------------------------------------------
section "utils::json_escape / csv_escape / html_escape"
# ---------------------------------------------------------------------------
assert_eq '\"x\"' "$(utils::json_escape '"x"')" "json_escape aspas"
assert_contains '&lt;b&gt;' "$(utils::html_escape '<b>')" "html_escape tags"
assert_eq '"a,b"' "$(utils::csv_escape 'a,b')" "csv_escape virgula"

# ---------------------------------------------------------------------------
section "result store"
# ---------------------------------------------------------------------------
utils::result_reset
utils::result_set foo.bar "valor1"
assert_eq "valor1" "$(utils::result_get foo.bar)" "result_get retorna valor"
utils::result_set foo.bar "valor2"
assert_eq "valor2" "$(utils::result_get foo.bar)" "result_set sobrescreve"
if utils::result_has foo.bar; then _ok "result_has verdadeiro"; else _no "result_has verdadeiro"; fi
if utils::result_has nao.existe; then _no "result_has falso"; else _ok "result_has falso"; fi

# ---------------------------------------------------------------------------
section "cache get/set com TTL"
# ---------------------------------------------------------------------------
export WEBAUDIT_CACHE_ENABLED=1
utils::cache_set testns chave 300 "conteudo-cache"
got="$(utils::cache_get testns chave)"
assert_eq "conteudo-cache" "${got}" "cache retorna valor dentro do TTL"
utils::cache_set testns expirada -100 "obsoleto"
got_expired="$(utils::cache_get testns expirada 2>/dev/null || true)"
assert_eq "" "${got_expired}" "cache expira quando TTL vencido"

# ---------------------------------------------------------------------------
section "detecção de SO / has"
# ---------------------------------------------------------------------------
utils::detect_os
assert_contains "${WEBAUDIT_OS}" "linux macos bsd unknown" "detect_os define valor conhecido"
if utils::has bash; then _ok "has encontra bash"; else _no "has encontra bash"; fi

# ---------------------------------------------------------------------------
section "dns::detect_cdn"
# ---------------------------------------------------------------------------
# shellcheck source=/dev/null
source "${LIB}/dns.sh"
assert_eq "Cloudflare" "$(dns::detect_cdn 'x.cloudflare.net')" "cdn cloudflare"
assert_eq "Akamai" "$(dns::detect_cdn 'e123.akamaiedge.net')" "cdn akamai"
assert_eq "Amazon CloudFront" "$(dns::detect_cdn 'd1.cloudfront.net')" "cdn cloudfront"

# ---------------------------------------------------------------------------
section "server::detect_software / detect_os"
# ---------------------------------------------------------------------------
# shellcheck source=/dev/null
source "${LIB}/server.sh"
assert_eq "nginx" "$(server::detect_software 'nginx/1.24.0')" "detecta nginx"
assert_eq "Apache" "$(server::detect_software 'Apache/2.4.57 (Ubuntu)')" "detecta apache"
assert_contains "Ubuntu" "$(server::detect_os 'Apache/2.4.57 (Ubuntu)')" "detecta ubuntu"

# ---------------------------------------------------------------------------
section "cli::parse - flags básicas"
# ---------------------------------------------------------------------------
# shellcheck source=/dev/null
source "${LIB}/cli.sh"
WEBAUDIT_TARGETS=()
# shellcheck disable=SC2034  # lido dentro de cli::parse
WEBAUDIT_HOSTFILE=""
cli::parse --json -t 5 -P 8443 exemplo.com >/dev/null 2>&1 || true
assert_eq "json" "${WEBAUDIT_OUTPUT}" "flag --json define saida"
assert_eq "5" "${WEBAUDIT_TIMEOUT}" "flag -t define timeout"
assert_eq "8443" "${WEBAUDIT_PORT_HTTPS}" "flag -P define porta https"
assert_eq "exemplo.com" "${WEBAUDIT_TARGETS[0]}" "alvo posicional capturado"

# ---------------------------------------------------------------------------
section "webaudit::normalize_target"
# ---------------------------------------------------------------------------
# shellcheck source=/dev/null
# normalize_target vive no script principal; replicamos a mesma lógica.
WEBAUDIT_PORT_HTTPS=443
webaudit::normalize_target() {
  local raw="$1"
  local host="${raw}"
  local port="${WEBAUDIT_PORT_HTTPS}"
  host="${host#http://}"; host="${host#https://}"
  host="${host%%/*}"
  if [[ "${host}" == *:* && "${host}" != *]:* ]]; then
    local p="${host##*:}"; host="${host%%:*}"
    [[ "${p}" =~ ^[0-9]+$ ]] && port="${p}"
  fi
  printf '%s %s' "${host}" "${port}"
}
read -r nh np < <(webaudit::normalize_target 'https://site.com/path?x=1')
assert_eq "site.com" "${nh}" "remove esquema e caminho"
read -r nh np < <(webaudit::normalize_target 'site.com:9443')
assert_eq "site.com" "${nh}" "extrai host de host:porta"
assert_eq "9443" "${np}" "porta extraida junto ao host"

# ---------------------------------------------------------------------------
section "sintaxe de todos os arquivos (bash -n)"
# ---------------------------------------------------------------------------
for f in "${ROOT}/webaudit.sh" "${LIB}"/*.sh; do
  if bash -n "${f}" 2>/dev/null; then _ok "sintaxe $(basename "${f}")"; else _no "sintaxe $(basename "${f}")"; fi
done

# ---------------------------------------------------------------------------
section "integração (rede)"
# ---------------------------------------------------------------------------
if [[ "${WEBAUDIT_TEST_NET:-0}" == "1" ]]; then
  out="$("${ROOT}/webaudit.sh" --no-color -q -t 15 example.com 2>/dev/null)"; rc=$?
  assert_contains "example.com" "${out}" "run real menciona host"
  case "${rc}" in 0|1|2) _ok "exit code de negocio (${rc})" ;; *) _no "exit code inesperado (${rc})" ;; esac
  json="$("${ROOT}/webaudit.sh" --no-color --json -t 15 example.com 2>/dev/null)"
  assert_contains '"host": "example.com"' "${json}" "saida json valida"
else
  printf '  (pulado - defina WEBAUDIT_TEST_NET=1 para habilitar)\n'
fi

# ---------------------------------------------------------------------------
# Resumo
# ---------------------------------------------------------------------------
printf '\n\033[1m== Resumo ==\033[0m\n'
printf 'Passou: %d   Falhou: %d\n' "${PASS}" "${FAIL}"
if (( FAIL > 0 )); then
  printf '\nTestes com falha:\n'
  for n in "${FAILED_NAMES[@]}"; do printf '  - %s\n' "${n}"; done
  exit 1
fi
printf '\nTodos os testes passaram.\n'
exit 0
