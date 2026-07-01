#!/usr/bin/env bash
#
# cve.sh - Consulta de vulnerabilidades conhecidas (CVEs).
#
# Responsabilidade única: dado software+versão, consultar bases oficiais de
# vulnerabilidades e resumir/detalhar os achados. Nunca utiliza Vulners.
#
# Estratégia (NVD 2.0):
#   1. Correlação por CPE via "virtualMatchString" (preciso, baseado nas
#      applicability statements da CVE). Fallback para "keywordSearch" quando
#      não há mapeamento de CPE para o software.
#   2. Paginação oficial: startIndex incrementado por resultsPerPage (2000)
#      até alcançar totalResults, respeitando o teto WEBAUDIT_CVE_MAX.
#   3. Rate limit conforme a NVD: sem chave ~6s entre requisições; com chave
#      (--nvd-key) ~0,6s.
#
# Saídas gravadas no result store:
#   cve.count   -> total real informado pela NVD (totalResults)
#   cve.shown   -> quantidade efetivamente listada (após o teto)
#   cve.method  -> "CPE" ou "keyword"
#   cve.status  -> texto para o relatório
#   cve.list    -> uma linha por CVE (id, CVSS, severidade, data, link, desc)
# Detalhe completo (JSON) em WEBAUDIT_CVE_JSON, embutido na saída --json.
#
# Requer `jq`. Resultados cacheados (namespace "cve", 12h).
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_CVE_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_CVE_LOADED=1

WEBAUDIT_NVD_API="https://services.nvd.nist.gov/rest/json/cves/2.0"
WEBAUDIT_OSV_API="https://api.osv.dev/v1/query"
# Detalhe JSON do host corrente (resetado por alvo em cve::run).
# Lido por json.sh (uso cruzado que o ShellCheck não enxerga).
# shellcheck disable=SC2034
WEBAUDIT_CVE_JSON=""

# cve::run <host> - orquestra a consulta.
cve::run() {
  WEBAUDIT_CVE_JSON=""

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
    utils::result_set cve.status "jq ausente - consulta de CVE indisponivel"
    utils::result_set cve.count "0"
    return 0
  fi

  utils::debug "CVE: consultando ${sw} ${ver}"

  local merged="" method="" cpe
  cpe="$(cve::_cpe "${sw}" "${ver}")"

  if [[ -n "${cpe}" ]]; then
    merged="$(cve::_nvd_fetch_all virtualMatchString "${cpe}" || true)"
    method="CPE"
  fi

  # Fallback por keyword quando não há CPE ou a busca por CPE não retornou nada.
  local total_probe=0
  if [[ -n "${merged}" ]]; then
    total_probe="$(printf '%s' "${merged}" | jq -r '.totalResults // 0' 2>/dev/null || echo 0)"
  fi
  if [[ -z "${merged}" || "${total_probe}" == "0" ]]; then
    local kw; kw="$(cve::_nvd_keyword "${sw}") ${ver}"
    merged="$(cve::_nvd_fetch_all keywordSearch "${kw}" || true)"
    method="keyword"
  fi

  if [[ -z "${merged}" ]]; then
    utils::result_set cve.status "Nenhuma conhecida"
    utils::result_set cve.count "0"
    return 0
  fi

  local total
  total="$(printf '%s' "${merged}" | jq -r '.totalResults // 0' 2>/dev/null || echo 0)"
  [[ "${total}" =~ ^[0-9]+$ ]] || total=0

  # Enriquecimento e recorte pelo teto.
  local enriched
  enriched="$(cve::_enrich_json "${merged}")"
  [[ -n "${enriched}" ]] || enriched="[]"
  # shellcheck disable=SC2034  # consumido por json.sh
  WEBAUDIT_CVE_JSON="${enriched}"

  local shown
  shown="$(printf '%s' "${enriched}" | jq 'length' 2>/dev/null || echo 0)"

  utils::result_set cve.count "${total}"
  utils::result_set cve.shown "${shown}"
  utils::result_set cve.method "${method}"

  if [[ "${total}" == "0" ]]; then
    utils::result_set cve.status "Nenhuma conhecida (via ${method})"
    return 0
  fi

  local status="${total} vulnerabilidade(s) encontrada(s) via ${method}"
  if (( shown < total )); then
    status+=" (exibindo ${shown}; ajuste com --cve-max)"
  fi
  utils::result_set cve.status "${status}"

  local list
  list="$(cve::_text_from_json "${enriched}")"
  [[ -n "${list}" ]] && utils::result_set cve.list "${list}"
}

# ---------------------------------------------------------------------------
# NVD: coleta paginada
# ---------------------------------------------------------------------------

# cve::_nvd_fetch_all <param> <valor> - baixa todas as páginas e devolve
# {"totalResults":N,"vulnerabilities":[...]} (recortado por WEBAUDIT_CVE_MAX).
cve::_nvd_fetch_all() {
  local param="$1" val="$2"
  local ck="nvdall:${param}:${val}:${WEBAUDIT_CVE_MAX}"
  local merged
  if merged="$(utils::cache_get cve "${ck}")"; then
    printf '%s' "${merged}"
    return 0
  fi
  utils::has jq || return 1

  local enc; enc="$(cve::_urlencode "${val}")"
  local page="${WEBAUDIT_NVD_PAGE:-2000}"
  local idx=0 total=-1 got=0
  local arrays=""
  local -a hdr; cve::_nvd_headers hdr

  while :; do
    local url body
    url="${WEBAUDIT_NVD_API}?${param}=${enc}&resultsPerPage=${page}&startIndex=${idx}&noRejected"
    body="$(cve::_curl "${url}" "${hdr[@]}")"
    [[ -n "${body}" ]] || break

    if (( total < 0 )); then
      total="$(printf '%s' "${body}" | jq -r '.totalResults // 0' 2>/dev/null || echo 0)"
      [[ "${total}" =~ ^[0-9]+$ ]] || total=0
    fi

    local chunk n
    chunk="$(printf '%s' "${body}" | jq -c '.vulnerabilities // []' 2>/dev/null || echo '[]')"
    n="$(printf '%s' "${chunk}" | jq 'length' 2>/dev/null || echo 0)"
    [[ "${n}" =~ ^[0-9]+$ ]] || n=0
    arrays+="${chunk}"$'\n'
    got=$(( got + n ))
    idx=$(( idx + page ))

    (( n == 0 )) && break
    (( total >= 0 && idx >= total )) && break
    (( WEBAUDIT_CVE_MAX > 0 && got >= WEBAUDIT_CVE_MAX )) && break
    cve::_sleep
  done

  merged="$(printf '%s' "${arrays}" | jq -s -c --argjson total "${total:-0}" \
    '{totalResults: $total, vulnerabilities: (add // [])}' 2>/dev/null || true)"
  [[ -n "${merged}" ]] || return 1
  utils::cache_set cve "${ck}" 43200 "${merged}"
  printf '%s' "${merged}"
}

# cve::_nvd_headers <nome_do_array> - popula headers (apiKey se houver chave).
cve::_nvd_headers() {
  local -n _h="$1"; _h=()
  [[ -n "${WEBAUDIT_NVD_API_KEY:-}" ]] && _h=(-H "apiKey: ${WEBAUDIT_NVD_API_KEY}")
}

# cve::_sleep - respeita o rate limit oficial da NVD.
cve::_sleep() {
  if [[ -n "${WEBAUDIT_NVD_API_KEY:-}" ]]; then
    sleep 0.6
  else
    sleep 6
  fi
}

# ---------------------------------------------------------------------------
# Transformações JSON
# ---------------------------------------------------------------------------

# cve::_enrich_json <merged> - array JSON detalhado, ordenado por CVSS desc e
# recortado por WEBAUDIT_CVE_MAX (0 = ilimitado).
cve::_enrich_json() {
  local merged="$1"
  local maxarg="${WEBAUDIT_CVE_MAX:-0}"
  [[ "${maxarg}" =~ ^[0-9]+$ ]] || maxarg=0
  printf '%s' "${merged}" | jq -c --argjson max "${maxarg}" '
    (.vulnerabilities // []) | map(.cve) | map(
      {
        id: .id,
        published: (.published[0:10]),
        lastModified: (.lastModified[0:10]),
        status: .vulnStatus,
        cvss: (
          (.metrics.cvssMetricV31[0] // .metrics.cvssMetricV30[0] // .metrics.cvssMetricV2[0]) as $m |
          if $m then {
            version: ($m.cvssData.version // "2.0"),
            score: ($m.cvssData.baseScore),
            severity: ($m.cvssData.baseSeverity // $m.baseSeverity // "N/A"),
            vector: ($m.cvssData.vectorString // null)
          } else null end
        ),
        cwe: ([ .weaknesses[]?.description[]? | select(.lang=="en") | .value ] | unique),
        description: ([ .descriptions[]? | select(.lang=="en") | .value ] | first // ""),
        affected: ([ .configurations[]?.nodes[]?.cpeMatch[]?
                     | select(.vulnerable==true)
                     | { cpe: .criteria,
                         versionStartIncluding: .versionStartIncluding,
                         versionStartExcluding: .versionStartExcluding,
                         versionEndIncluding:   .versionEndIncluding,
                         versionEndExcluding:   .versionEndExcluding } ]),
        kev: (has("cisaVulnerabilityName")),
        references: ([ .references[]?.url ] | unique),
        url: ("https://nvd.nist.gov/vuln/detail/" + .id)
      }
    )
    | sort_by(.cvss.score // 0) | reverse
    | if $max > 0 then .[0:$max] else . end
  ' 2>/dev/null || printf '[]'
}

# cve::_text_from_json <enriched> - linhas TSV para o relatório em texto.
cve::_text_from_json() {
  printf '%s' "$1" | jq -r '
    .[] | [
      .id,
      "CVSS \(.cvss.score // "N/A")",
      (.cvss.severity // "N/A"),
      .published,
      .url,
      (.description[0:140])
    ] | @tsv
  ' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# OSV.dev (mantido como fonte auxiliar, sob demanda)
# ---------------------------------------------------------------------------

# cve::_query_osv <software> <versao> - consulta OSV.dev (cobertura parcial).
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
  ' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Helpers de mapeamento
# ---------------------------------------------------------------------------

# cve::_cpe <software> <versao> - monta um CPE 2.3 parcial para a NVD.
cve::_cpe() {
  local sw ver vendor product
  sw="$(printf '%s' "$1" | utils::lower)"
  ver="$2"
  case "${sw}" in
    nginx)     vendor="f5";           product="nginx" ;;
    openresty) vendor="openresty";     product="openresty" ;;
    apache)    vendor="apache";        product="http_server" ;;
    tomcat)    vendor="apache";        product="tomcat" ;;
    haproxy)   vendor="haproxy";       product="haproxy" ;;
    litespeed) vendor="litespeedtech"; product="litespeed_web_server" ;;
    iis)       vendor="microsoft";     product="internet_information_services" ;;
    caddy)     vendor="caddyserver";   product="caddy" ;;
    envoy)     vendor="envoyproxy";    product="envoy" ;;
    *)         printf ''; return 0 ;;
  esac
  printf 'cpe:2.3:a:%s:%s:%s' "${vendor}" "${product}" "${ver}"
}

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

cve::_osv_ecosystem() { printf ''; }

cve::_osv_name() {
  case "$(printf '%s' "$1" | utils::lower)" in
    nginx) printf 'nginx' ;;
    *)     printf '' ;;
  esac
}

# cve::_curl <url> <headers...> - GET/POST com timeout e headers extras.
cve::_curl() {
  local url="$1"; shift
  local -a opts; http::_curl_base opts
  curl "${opts[@]}" "$@" "${url}" 2>/dev/null || true
}

# cve::_urlencode <str> - encode para query string.
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
