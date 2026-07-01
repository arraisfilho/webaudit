#!/usr/bin/env bash
#
# http.sh - Verificações de camada HTTP via curl.
#
# Responsabilidade única: coletar comportamento HTTP/HTTPS do alvo:
#   - Acessibilidade em http:// e https://
#   - Cadeia de redirects e detecção de loop
#   - Código de status, tempo de resposta, protocolo negociado
#   - Métodos suportados (HEAD/OPTIONS/GET)
#   - Content-Type, Content-Length, Transfer-Encoding
#   - Suporte a HTTP/2 e HTTP/3 (quando o curl tiver os recursos)
#
# Os cabeçalhos brutos são armazenados em WEBAUDIT_RAW_HEADERS para reuso
# pelos módulos headers/security/fingerprint (evita novas requisições).
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_HTTP_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_HTTP_LOADED=1

WEBAUDIT_RAW_HEADERS=""
WEBAUDIT_BASE_URL=""

# http::_curl_base - array de opções comuns do curl.
http::_curl_base() {
  local -n _out="$1"
  _out=(
    --silent --show-error
    --max-time "${WEBAUDIT_TIMEOUT}"
    --connect-timeout "${WEBAUDIT_TIMEOUT}"
    --user-agent "${WEBAUDIT_USER_AGENT}"
    --insecure   # a validação real de cert é feita pelo módulo cert (openssl)
  )
  [[ -n "${WEBAUDIT_PROXY}" ]] && _out+=( --proxy "${WEBAUDIT_PROXY}" )
}

# http::_probe <url> - faz uma requisição HEAD seguindo redirects e captura
# métricas via -w. Ecoa uma linha "code|time|proto|url_efetiva|num_redirects".
http::_probe() {
  local url="$1"
  local -a opts; http::_curl_base opts
  curl "${opts[@]}" --location --head \
    --write-out '%{http_code}|%{time_total}|%{http_version}|%{url_effective}|%{num_redirects}' \
    --output /dev/null "${url}" 2>/dev/null || printf '000|0|0||0'
}

# http::_fetch_headers <url> - captura cabeçalhos brutos seguindo redirects.
http::_fetch_headers() {
  local url="$1"
  local -a opts; http::_curl_base opts
  curl "${opts[@]}" --location --dump-header - --output /dev/null "${url}" 2>/dev/null || true
}

# http::_methods <url> - detecta métodos via OPTIONS (Allow) e testes diretos.
http::_methods() {
  local url="$1"
  local -a opts; http::_curl_base opts
  local allow methods=""

  # 1) Header Allow via OPTIONS.
  allow="$(curl "${opts[@]}" -X OPTIONS --dump-header - --output /dev/null "${url}" 2>/dev/null \
            | awk -F': ' 'tolower($1)=="allow"{print $2}' | tr -d '\r' | utils::trim)"
  [[ -n "${allow}" ]] && methods="${allow}"

  # 2) Sondagem direta HEAD/GET se Allow ausente.
  if [[ -z "${methods}" ]]; then
    local m code
    for m in GET HEAD OPTIONS; do
      code="$(curl "${opts[@]}" -X "${m}" --write-out '%{http_code}' --output /dev/null "${url}" 2>/dev/null)"
      if [[ "${code}" =~ ^[23] ]]; then
        methods="${methods:+${methods}, }${m}"
      fi
    done
  fi
  printf '%s' "${methods}"
}

# http::run <host> - orquestra a coleta HTTP.
http::run() {
  local host="$1"
  local ph="${WEBAUDIT_PORT_HTTP}" ps="${WEBAUDIT_PORT_HTTPS}"
  local http_url="http://${host}:${ph}/"
  local https_url="https://${host}:${ps}/"

  utils::debug "HTTP: sondando ${host}"

  # --- HTTP simples ---
  local h_line h_code h_url
  h_line="$(http::_probe "${http_url}")"
  h_code="${h_line%%|*}"
  h_url="$(printf '%s' "${h_line}" | cut -d'|' -f4)"
  if [[ "${h_code}" != "000" ]]; then
    utils::result_set http.status "OK"
    utils::result_set http.code "${h_code}"
    # Detecta upgrade para https no redirect.
    if [[ "${h_url}" == https://* ]]; then
      utils::result_set http.redirect_https "Sim"
    else
      utils::result_set http.redirect_https "Nao"
    fi
  else
    utils::result_set http.status "CRITICAL"
    utils::result_set http.code "-"
  fi

  # --- HTTPS ---
  local s_line s_code s_time s_proto s_url s_redirs
  s_line="$(http::_probe "${https_url}")"
  IFS='|' read -r s_code s_time s_proto s_url s_redirs <<<"${s_line}"

  if [[ "${s_code}" != "000" ]]; then
    utils::result_set https.status "OK"
    utils::result_set https.code "${s_code}"
    utils::result_set https.time_s "${s_time}"
    utils::result_set https.redirects "${s_redirs}"
    utils::result_set https.final_url "${s_url}"
    WEBAUDIT_BASE_URL="${https_url}"
  else
    utils::result_set https.status "CRITICAL"
    utils::result_set https.code "-"
    WEBAUDIT_BASE_URL="${http_url}"
  fi

  # Detecção de redirect loop (curl retorna 47/erro; num_redirects alto).
  if [[ "${s_redirs:-0}" =~ ^[0-9]+$ ]] && (( ${s_redirs:-0} >= 10 )); then
    utils::result_set http.redirect_loop "Sim"
    utils::warn "HTTP: possivel redirect loop (${s_redirs} saltos)"
  else
    utils::result_set http.redirect_loop "Nao"
  fi

  # --- Cabeçalhos brutos (reusados por outros módulos) ---
  WEBAUDIT_RAW_HEADERS="$(http::_fetch_headers "${WEBAUDIT_BASE_URL}")"
  export WEBAUDIT_RAW_HEADERS WEBAUDIT_BASE_URL

  # Content-Type / Length / Transfer-Encoding do último response.
  local ct cl te
  ct="$(http::header_value 'content-type')"
  cl="$(http::header_value 'content-length')"
  te="$(http::header_value 'transfer-encoding')"
  utils::result_set http.content_type "${ct}"
  utils::result_set http.content_length "${cl}"
  utils::result_set http.transfer_encoding "${te}"

  # Protocolo HTTP negociado.
  case "${s_proto}" in
    3*) utils::result_set http.version "HTTP/3" ;;
    2*) utils::result_set http.version "HTTP/2" ;;
    1.1) utils::result_set http.version "HTTP/1.1" ;;
    1.0) utils::result_set http.version "HTTP/1.0" ;;
    *)   utils::result_set http.version "${s_proto:-desconhecido}" ;;
  esac

  # Métodos suportados.
  utils::result_set http.methods "$(http::_methods "${WEBAUDIT_BASE_URL}")"

  # HTTP/2 e HTTP/3.
  http::detect_http2 "${host}" "${ps}"
  http::detect_http3 "${host}" "${ps}"
}

# http::header_value <nome> - último valor de um cabeçalho (case-insensitive)
# a partir de WEBAUDIT_RAW_HEADERS.
http::header_value() {
  local name; name="$(printf '%s' "$1" | utils::lower)"
  printf '%s\n' "${WEBAUDIT_RAW_HEADERS}" \
    | awk -F': ' -v n="${name}" 'tolower($1)==n{v=$0; sub(/^[^:]*: /,"",v); gsub(/\r/,"",v); last=v} END{print last}' \
    | utils::trim
}

# http::detect_http2 <host> <porta>
http::detect_http2() {
  local host="$1" port="$2"
  local -a opts; http::_curl_base opts
  if curl "${opts[@]}" --http2 -I "https://${host}:${port}/" 2>/dev/null \
       | grep -qiE '^HTTP/2'; then
    utils::result_set http.http2 "Sim"
  else
    utils::result_set http.http2 "Nao"
  fi
}

# http::detect_http3 <host> <porta> - depende de curl com suporte a HTTP/3.
http::detect_http3() {
  local host="$1" port="$2"
  # Verifica se o curl foi compilado com HTTP3.
  if ! curl --version 2>/dev/null | grep -qiE 'HTTP3|http3'; then
    utils::result_set http.http3 "Indisponivel (curl sem HTTP/3)"
    return 0
  fi
  local -a opts; http::_curl_base opts
  if curl "${opts[@]}" --http3-only -I "https://${host}:${port}/" 2>/dev/null \
       | grep -qiE '^HTTP/3'; then
    utils::result_set http.http3 "Sim"
  else
    utils::result_set http.http3 "Nao"
  fi
}
