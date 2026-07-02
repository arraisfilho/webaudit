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
section "renderizadores report/json"
# ---------------------------------------------------------------------------
# shellcheck source=/dev/null
source "${LIB}/report.sh"
# shellcheck source=/dev/null
source "${LIB}/json.sh"
utils::result_reset
utils::result_set dns.ipv4 "93.184.216.34"
utils::result_set dns.status "OK"
utils::result_set tcp.status "OK"
utils::result_set http.status "OK"
utils::result_set https.status "OK"
utils::result_set https.code "200"
utils::result_set tls.rating "OK"
utils::result_set cert.status "OK"
utils::result_set sec.rating "OK"
utils::result_set cve.status "Nenhuma conhecida"
WEBAUDIT_CVE_JSON="[]"
_old_quiet="${WEBAUDIT_QUIET}"
WEBAUDIT_QUIET=0
_txt="$(report::text exemplo.com 1.00)"
WEBAUDIT_QUIET="${_old_quiet}"
assert_contains "Disponibilidade" "${_txt}" "report text tem secoes"
assert_contains "Codigo HTTPS" "${_txt}" "report text usa rotulos alinhaveis"
_json="$(json::emit exemplo.com 1.00)"
assert_contains '"results"' "${_json}" "json contem objeto results"
if utils::has jq; then
  assert_eq "93.184.216.34" "$(printf '%s' "${_json}" | jq -r '.results["dns.ipv4"]')" "json aninha resultados"
  assert_eq "null" "$(printf '%s' "${_json}" | jq -r '."dns.ipv4" // "null"')" "json nao duplica resultados no topo"
fi

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
section "deps::check_runtime helpers"
# ---------------------------------------------------------------------------
# shellcheck source=/dev/null
source "${LIB}/deps.sh"
if deps::_check_bash_version; then _ok "bash atende versao minima"; else _no "bash atende versao minima"; fi
assert_eq "curl, openssl, jq" "$(deps::_join ', ' curl openssl jq)" "deps join lista comandos"
_old_os="${WEBAUDIT_OS}"
WEBAUDIT_OS=macos
_mac_hints="$(deps::_print_install_hints 2>&1 >/dev/null)"
assert_contains "brew install" "${_mac_hints}" "deps sugere Homebrew no macOS"
WEBAUDIT_OS=linux
_linux_hints="$(deps::_print_install_hints 2>&1 >/dev/null)"
assert_contains "apt-get install" "${_linux_hints}" "deps sugere apt no Linux"
WEBAUDIT_OS="${_old_os}"

# ---------------------------------------------------------------------------
section "dns::detect_cdn"
# ---------------------------------------------------------------------------
# shellcheck source=/dev/null
source "${LIB}/dns.sh"
assert_eq "Cloudflare" "$(dns::detect_cdn 'x.cloudflare.net')" "cdn cloudflare"
assert_eq "Akamai" "$(dns::detect_cdn 'e123.akamaiedge.net')" "cdn akamai"
assert_eq "Amazon CloudFront" "$(dns::detect_cdn 'd1.cloudfront.net')" "cdn cloudfront"
if dns::is_ipv4_literal "10.1.1.223"; then _ok "detecta IPv4 literal"; else _no "detecta IPv4 literal"; fi
utils::result_reset
dns::run "10.1.1.223"
assert_eq "OK" "$(utils::result_get dns.status)" "dns literal IPv4 fica OK"
assert_eq "10.1.1.223" "$(utils::result_get dns.ipv4)" "dns literal IPv4 preserva endereco"

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
section "cve::_cpe / _enrich_json (offline)"
# ---------------------------------------------------------------------------
export WEBAUDIT_CVE_MAX=500 WEBAUDIT_NVD_PAGE=2000
# shellcheck source=/dev/null
source "${LIB}/http.sh"
# shellcheck source=/dev/null
source "${LIB}/cve.sh"
assert_eq "cpe:2.3:a:f5:nginx:1.20.0" "$(cve::_cpe nginx 1.20.0)" "cpe nginx -> f5:nginx"
assert_eq "cpe:2.3:a:apache:http_server:2.4.57" "$(cve::_cpe Apache 2.4.57)" "cpe apache http_server"
assert_eq "" "$(cve::_cpe softwaredesconhecido 1.0)" "cpe vazio p/ desconhecido (fallback keyword)"
WEBAUDIT_CVE_MAX=20 WEBAUDIT_NVD_PAGE=2000
assert_eq "20" "$(cve::_nvd_page_size)" "nvd page respeita cve-max"
WEBAUDIT_CVE_MAX=0 WEBAUDIT_NVD_PAGE=2000
assert_eq "2000" "$(cve::_nvd_page_size)" "nvd page usa maximo quando cve-max ilimitado"
WEBAUDIT_CVE_MAX=500

(
  cve::_nvd_fetch_page() { printf '{"totalResults":0,"vulnerabilities":[]}'; }
  cve::_nvd_fetch_all keywordSearch "apache 2.4.18" >/dev/null
)
assert_rc "0" "$?" "nvd fetch funciona sem api key"

(
  cve::_curl() { printf ''; }
  cve::_sleep() { :; }
  cve::_nvd_fetch_page "https://nvd.example.invalid" >/dev/null 2>&1
)
assert_rc "1" "$?" "nvd page vazia falha em vez de virar zero CVEs"

if utils::has jq; then
  _merged='{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2021-23017","published":"2021-06-01T00:00Z","lastModified":"2024-01-01T00:00Z","vulnStatus":"Analyzed","metrics":{"cvssMetricV31":[{"cvssData":{"version":"3.1","baseScore":7.7,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N"}}]},"weaknesses":[{"description":[{"lang":"en","value":"CWE-193"}]}],"descriptions":[{"lang":"en","value":"nginx resolver off-by-one"}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionEndExcluding":"1.20.1"}]}]}],"references":[{"url":"https://example/adv"}]}},{"cve":{"id":"CVE-2000-0001","published":"2000-01-01T00:00Z","lastModified":"2000-01-01T00:00Z","vulnStatus":"Analyzed","metrics":{"cvssMetricV2":[{"baseSeverity":"LOW","cvssData":{"version":"2.0","baseScore":2.1,"vectorString":"AV:L"}}]},"descriptions":[{"lang":"en","value":"exemplo antigo"}]}}]}'
  _enr="$(cve::_enrich_json "${_merged}")"
  assert_eq "2" "$(printf '%s' "${_enr}" | jq 'length')" "enrich mantem 2 CVEs"
  assert_eq "CVE-2021-23017" "$(printf '%s' "${_enr}" | jq -r '.[0].id')" "enrich ordena por CVSS desc"
  assert_eq "HIGH" "$(printf '%s' "${_enr}" | jq -r '.[0].cvss.severity')" "enrich extrai severidade v3.1"
  assert_eq "LOW" "$(printf '%s' "${_enr}" | jq -r '.[1].cvss.severity')" "enrich extrai severidade v2"
  assert_eq "1.20.1" "$(printf '%s' "${_enr}" | jq -r '.[0].affected[0].versionEndExcluding')" "enrich traz versao afetada"
  assert_eq "CWE-193" "$(printf '%s' "${_enr}" | jq -r '.[0].cwe[0]')" "enrich traz CWE"
  # recorte pelo teto
  WEBAUDIT_CVE_MAX=1
  assert_eq "1" "$(cve::_enrich_json "${_merged}" | jq 'length')" "cve-max recorta a lista"
  WEBAUDIT_CVE_MAX=500
  # linha de texto no formato esperado
  _line="$(cve::_text_from_json "${_enr}" | head -n1)"
  assert_contains "CVE-2021-23017" "${_line}" "texto contem o CVE-ID"
  assert_contains "CVSS 7.7" "${_line}" "texto contem CVSS"
else
  printf '  (jq ausente - testes de enriquecimento pulados)\n'
fi


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
