#!/usr/bin/env bash
#
# fingerprint.sh - Fingerprint do servidor por sinais indiretos.
#
# Responsabilidade única: inferir o software servidor quando o banner Server
# está ausente/mascarado, combinando sinais: ordem/conjunto de cabeçalhos,
# formato do ETag, cookies, cabeçalhos proprietários, comportamento em 404 e
# OPTIONS, e ALPN/HTTP2. Produz um palpite com nível de confiança.
#
# Não substitui o módulo server; complementa-o quando server.masked == Sim.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_FINGERPRINT_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_FINGERPRINT_LOADED=1

# fingerprint::_probe_404 <base_url> - captura cabeçalhos de uma URL inexistente.
fingerprint::_probe_404() {
  local base="$1"
  http::_curl_base
  local -a opts=("${WEBAUDIT_CURL_OPTS[@]}")
  local url="${base%/}/webaudit-nonexistent-$RANDOM"
  curl "${opts[@]}" --dump-header - --output /dev/null "${url}" 2>/dev/null || true
}

# fingerprint::run <host> - executa a heurística.
fingerprint::run() {
  local host="$1"
  utils::debug "FINGERPRINT: analisando sinais de ${host}"

  local raw="${WEBAUDIT_RAW_HEADERS}"
  local guesses="" confidence="baixa"

  # Sinal 1: cabeçalhos proprietários clássicos.
  local hdr_names; hdr_names="$(printf '%s\n' "${raw}" | awk -F':' '/:/{print tolower($1)}')"
  if printf '%s' "${hdr_names}" | grep -q 'x-litespeed'; then guesses+="LiteSpeed "; fi
  if printf '%s' "${hdr_names}" | grep -q 'x-aspnet-version\|x-aspnetmvc-version'; then guesses+="IIS/ASP.NET "; fi
  if printf '%s' "${hdr_names}" | grep -q 'x-envoy'; then guesses+="Envoy "; fi
  if printf '%s' "${raw}" | grep -qi 'cf-ray'; then guesses+="Cloudflare(edge) "; fi
  if printf '%s' "${raw}" | grep -qi '^x-served-by:.*cache'; then guesses+="Fastly(edge) "; fi

  # Sinal 2: cookies típicos.
  local setcookie; setcookie="$(printf '%s' "${raw}" | grep -i '^set-cookie:' || true)"
  if printf '%s' "${setcookie}" | grep -qi 'JSESSIONID'; then guesses+="Java(Tomcat/Jetty) "; fi
  if printf '%s' "${setcookie}" | grep -qi 'ASP.NET_SessionId\|ASPSESSION'; then guesses+="IIS/ASP.NET "; fi
  if printf '%s' "${setcookie}" | grep -qi 'PHPSESSID'; then guesses+="PHP "; fi

  # Sinal 3: formato do ETag (nginx usa hex-hex; apache formatos distintos).
  local etag; etag="$(http::header_value 'etag')"
  if [[ "${etag}" =~ ^\"?[0-9a-f]+-[0-9a-f]+\"?$ ]]; then guesses+="nginx/apache(etag) "; fi

  # Sinal 4: página 404 do servidor.
  local body404
  body404="$(fingerprint::_probe_404 "${WEBAUDIT_BASE_URL}")"
  local srv404; srv404="$(printf '%s' "${body404}" | awk -F': ' 'tolower($1)=="server"{print $2}' | tr -d '\r' | head -n1)"
  if [[ -n "${srv404}" ]]; then guesses+="${srv404}(404-banner) "; fi

  # Sinal 5: ALPN/HTTP2 sugere stack moderna (nginx/caddy/envoy).
  if [[ "$(utils::result_get http.http2)" == "Sim" ]]; then guesses+="http2 "; fi

  # Consolidação.
  guesses="$(printf '%s' "${guesses}" | utils::trim)"
  if [[ -n "${guesses}" ]]; then
    # Se há sinal forte (cabeçalho proprietário), confiança média/alta.
    if printf '%s' "${guesses}" | grep -qiE 'LiteSpeed|IIS|Envoy'; then
      confidence="media"
    fi
    utils::result_set fingerprint.guess "${guesses}"
    utils::result_set fingerprint.confidence "${confidence}"
  else
    utils::result_set fingerprint.guess "indeterminado"
    utils::result_set fingerprint.confidence "nenhuma"
  fi
}
