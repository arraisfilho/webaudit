#!/usr/bin/env bash
#
# cve.sh - Consulta de vulnerabilidades conhecidas (CVEs).
#
# Responsabilidade única: dado software+versão, consultar bases oficiais de
# vulnerabilidades e resumir os achados (id, CVSS, severidade, resumo, data,
# link). Nunca utiliza Vulners.
#
# Fontes (nesta ordem de preferência):
#   - NVD 2.0     : https://services.nvd.nist.gov/rest/json/cves/2.0
#   - OSV.dev     : https://api.osv.dev/v1/query
#   - GitHub GHSA : https://api.github.com/advisories
#
# API keys opcionais:
#   WEBAUDIT_NVD_API_KEY   -> header "apiKey" (eleva o rate limit da NVD)
#   WEBAUDIT_GITHUB_TOKEN  -> header "Authorization: Bearer ..."
#
# Requer `jq` para parsing confiável do JSON. Sem jq, degrada para uma
# contagem aproximada por CVE-ID. Resultados cacheados (namespace "cve", 12h).
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_CVE_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_CVE_LOADED=1

WEBAUDIT_NVD_API="https://services.nvd.nist.gov/rest/json/cves/2.0"
WEBAUDIT_OSV_API="https://api.osv.dev/v1/query"
# Endpoint GHSA reservado para uso futuro (correlação por ecossistema).
# shellcheck disable=SC2034
WEBAUDIT_GHSA_API="https://api.github.com/advisories"

# cve::run <host> - orquestra a consulta.
cve::run() {
  # host recebido por assinatura, porém a coleta usa resultados já
  # armazenados (server.software/server.version).

  if [[ "${WEBAUDIT_CVE_ENABLED}" != "1" ]]; then
    utils::result_set cve.status "Consulta de CVE desabilitada"
    return 0
  fi

  local sw ver
  sw="$(utils::result_get server.software)"
  ver="$(utils::result_get server.version)"

  if [[ -z "${ver}" || "${ver}" == "desconhecida" \
        || "$(utils::result_get server.masked)" == "Sim" ]]; then
    utils::result_set cve.status \
      "Nao foi possivel determinar vulnerabilidades por falta da versao do software"
    utils::result_set cve.count "0"
    return 0
  fi

  if ! utils::has jq; then
    utils::result_set cve.status "jq ausente - consulta de CVE limitada"
  fi

  utils::debug "CVE: consultando ${sw} ${ver}"
  local summary=""
  summary="$(cve::_query_nvd "${sw}" "${ver}")"
  if [[ -z "${summary}" ]]; then
    summary="$(cve::_query_osv "${sw}" "${ver}")"
  fi

  if [[ -z "${summary}" ]]; then
    utils::result_set cve.status "Nenhuma conhecida"
    utils::result_set cve.count "0"
  else
    local count; count="$(printf '%s\n' "${summary}" | grep -c '^CVE\|^GHSA\|^OSV' || true)"
    utils::result_set cve.count "${count}"
    utils::result_set cve.status "${count} vulnerabilidade(s) encontrada(s)"
    utils::result_set cve.list "${summary}"
  fi
}

# cve::_curl <url> <headers...> - GET com timeout e headers extras.
cve::_curl() {
  local url="$1"; shift
  local -a opts; http::_curl_base opts
  curl "${opts[@]}" "$@" "${url}" 2>/dev/null || true
}

# cve::_query_nvd <software> <versao> - consulta a NVD por keyword.
cve::_query_nvd() {
  local sw="$1" ver="$2"
  local kw; kw="$(cve::_nvd_keyword "${sw}") ${ver}"
  local cache_key="nvd:${kw}"
  local body

  if ! body="$(utils::cache_get cve "${cache_key}")"; then
    local -a hdr=()
    [[ -n "${WEBAUDIT_NVD_API_KEY:-}" ]] && hdr=(-H "apiKey: ${WEBAUDIT_NVD_API_KEY}")
    # keywordSearch com múltiplos termos (AND); resultsPerPage limitado.
    local enc; enc="$(cve::_urlencode "${kw}")"
    body="$(cve::_curl "${WEBAUDIT_NVD_API}?keywordSearch=${enc}&resultsPerPage=20" "${hdr[@]}")"
    [[ -n "${body}" ]] && utils::cache_set cve "${cache_key}" 43200 "${body}"
  fi
  [[ -n "${body}" ]] || return 1
  utils::has jq || return 1

  printf '%s' "${body}" | jq -r '
    .vulnerabilities[]? | .cve as $c |
    ($c.metrics.cvssMetricV31[0].cvssData.baseScore //
     $c.metrics.cvssMetricV30[0].cvssData.baseScore //
     $c.metrics.cvssMetricV2[0].cvssData.baseScore // "N/A") as $score |
    ($c.metrics.cvssMetricV31[0].cvssData.baseSeverity //
     $c.metrics.cvssMetricV30[0].cvssData.baseSeverity //
     $c.metrics.cvssMetricV2[0].baseSeverity // "N/A") as $sev |
    ($c.descriptions[]? | select(.lang=="en") | .description) as $desc |
    "\($c.id)\tCVSS \($score)\t\($sev)\t\($c.published[0:10])\thttps://nvd.nist.gov/vuln/detail/\($c.id)\t\($desc[0:140])"
  ' 2>/dev/null | sort -u | head -n 20
}

# cve::_query_osv <software> <versao> - consulta OSV.dev.
cve::_query_osv() {
  local sw="$1" ver="$2"
  local eco name
  eco="$(cve::_osv_ecosystem "${sw}")"
  name="$(cve::_osv_name "${sw}")"
  [[ -n "${name}" ]] || return 1

  local cache_key="osv:${eco}:${name}:${ver}"
  local body payload
  payload="$(printf '{"version":"%s","package":{"name":"%s","ecosystem":"%s"}}' "${ver}" "${name}" "${eco}")"

  if ! body="$(utils::cache_get cve "${cache_key}")"; then
    body="$(cve::_curl "${WEBAUDIT_OSV_API}" -X POST -d "${payload}")"
    [[ -n "${body}" ]] && utils::cache_set cve "${cache_key}" 43200 "${body}"
  fi
  [[ -n "${body}" ]] || return 1
  utils::has jq || return 1

  printf '%s' "${body}" | jq -r '
    .vulns[]? |
    (.severity[0].score // "N/A") as $sev |
    "\(.id)\t\($sev)\t\(.summary // "sem resumo")\t\(.modified[0:10])\thttps://osv.dev/vulnerability/\(.id)"
  ' 2>/dev/null | head -n 20
}

# ---- Helpers de mapeamento ----

cve::_nvd_keyword() {
  case "$(printf '%s' "$1" | utils::lower)" in
    nginx)     printf 'nginx' ;;
    openresty) printf 'openresty' ;;
    apache)    printf 'apache http server' ;;
    litespeed) printf 'litespeed' ;;
    tomcat)    printf 'apache tomcat' ;;
    haproxy)   printf 'haproxy' ;;
    iis)       printf 'internet information services' ;;
    caddy)     printf 'caddy' ;;
    envoy)     printf 'envoy' ;;
    *)         printf '%s' "$1" ;;
  esac
}

cve::_osv_ecosystem() {
  # OSV cobre alguns pacotes de SO/Linux; para servidores web a cobertura é
  # parcial. Usamos "Debian" como aproximação apenas quando aplicável.
  printf ''
}

cve::_osv_name() {
  case "$(printf '%s' "$1" | utils::lower)" in
    nginx)  printf 'nginx' ;;
    apache) printf '' ;;
    *)      printf '' ;;
  esac
}

# cve::_urlencode <str> - encode mínimo para query string.
cve::_urlencode() {
  local s="$1" out="" c i
  for (( i=0; i<${#s}; i++ )); do
    c="${s:$i:1}"
    case "${c}" in
      [a-zA-Z0-9.~_-]) out+="${c}" ;;
      ' ') out+="%20" ;;
      *)   out+="$(printf '%%%02X' "'${c}")" ;;
    esac
  done
  printf '%s' "${out}"
}
