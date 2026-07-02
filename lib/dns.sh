#!/usr/bin/env bash
#
# dns.sh - Resolução e análise DNS.
#
# Responsabilidade única: resolver registros DNS do host alvo (IPv4, IPv6,
# CNAME, MX, TXT, NS, TTL, PTR/reverse), medir tempo de resolução e detectar
# provedores de CDN a partir de CNAME/NS/IP.
#
# Usa `dig` quando disponível (mais rico); faz fallback para `host` e, por
# último, para `getent`/`nslookup`. Resultados vão para o result store e para
# o cache local (namespace "dns").
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_DNS_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_DNS_LOADED=1

# dns::_dig <tipo> <nome> - consulta dig e retorna somente respostas.
dns::_dig() {
  local rtype="$1" name="$2"
  dig +short +time=3 +tries=2 "${rtype}" "${name}" 2>/dev/null \
    | grep -v '^;' || true
}

# dns::_dig_ttl <tipo> <nome> - retorna o menor TTL do rrset (via seção answer).
dns::_dig_ttl() {
  local rtype="$1" name="$2"
  dig +noall +answer +time=3 +tries=2 "${rtype}" "${name}" 2>/dev/null \
    | awk '{print $2}' | sort -n | head -n1 || true
}

# dns::_host <tipo> <nome> - fallback usando host(1).
dns::_host() {
  local rtype="$1" name="$2"
  case "${rtype}" in
    A)     host -t A "${name}" 2>/dev/null | awk '/has address/{print $NF}' ;;
    AAAA)  host -t AAAA "${name}" 2>/dev/null | awk '/has IPv6 address/{print $NF}' ;;
    CNAME) host -t CNAME "${name}" 2>/dev/null | awk '/alias for/{print $NF}' ;;
    MX)    host -t MX "${name}" 2>/dev/null | awk '/mail is handled/{print $NF}' ;;
    TXT)   host -t TXT "${name}" 2>/dev/null | sed -n 's/.*descriptive text //p' ;;
    NS)    host -t NS "${name}" 2>/dev/null | awk '/name server/{print $NF}' ;;
  esac
}

# dns::query <tipo> <nome> - abstrai dig/host.
dns::query() {
  local rtype="$1" name="$2"
  if utils::has dig; then
    dns::_dig "${rtype}" "${name}"
  elif utils::has host; then
    dns::_host "${rtype}" "${name}"
  else
    # Último recurso: getent (apenas A/AAAA).
    case "${rtype}" in
      A)    getent ahostsv4 "${name}" 2>/dev/null | awk '{print $1}' | sort -u ;;
      AAAA) getent ahostsv6 "${name}" 2>/dev/null | awk '{print $1}' | sort -u ;;
    esac
  fi
}

# dns::detect_cdn <cname_ns_ip_blob> - heurística de detecção de CDN/edge.
dns::detect_cdn() {
  local blob; blob="$(printf '%s' "$1" | utils::lower)"
  case "${blob}" in
    *cloudflare*)                 printf 'Cloudflare' ;;
    *akamai*)                     printf 'Akamai' ;;
    *fastly*)                     printf 'Fastly' ;;
    *cloudfront*)                 printf 'Amazon CloudFront' ;;
    *azurefd*|*azureedge*|*trafficmanager*|*afdxin*) printf 'Azure Front Door' ;;
    *googleusercontent*|*ghs.google*|*1e100*) printf 'Google Cloud CDN' ;;
    *)                            printf '' ;;
  esac
}

dns::is_ipv4_literal() {
  local ip="$1" part
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local old_ifs="${IFS}"
  IFS='.'
  for part in ${ip}; do
    [[ "${part}" =~ ^[0-9]+$ ]] || { IFS="${old_ifs}"; return 1; }
    (( part <= 255 )) || { IFS="${old_ifs}"; return 1; }
  done
  IFS="${old_ifs}"
  return 0
}

dns::is_ipv6_literal() {
  local ip="$1"
  [[ "${ip}" == *:* && "${ip}" =~ ^[0-9A-Fa-f:]+$ ]]
}

# dns::run <host> - executa toda a coleta DNS.
dns::run() {
  local host="$1"
  utils::debug "DNS: resolvendo ${host}"

  local t0 t1 elapsed
  t0="$(dns::_millis)"

  if dns::is_ipv4_literal "${host}" || dns::is_ipv6_literal "${host}"; then
    t1="$(dns::_millis)"
    elapsed="$(dns::_delta "${t0}" "${t1}")"

    if dns::is_ipv4_literal "${host}"; then
      utils::result_set dns.ipv4 "${host}"
      utils::result_set dns.ipv6 ""
      local ptr; ptr="$(dns::reverse "${host}")"
      utils::result_set dns.ptr "${ptr}"
      utils::result_set dns.cdn "$(dns::detect_cdn "${ptr}")"
    else
      utils::result_set dns.ipv4 ""
      utils::result_set dns.ipv6 "${host}"
      utils::result_set dns.cdn ""
    fi

    utils::result_set dns.cname ""
    utils::result_set dns.ns ""
    utils::result_set dns.mx ""
    utils::result_set dns.txt_count "0"
    utils::result_set dns.ttl ""
    utils::result_set dns.time_ms "${elapsed}"
    utils::result_set dns.status "OK"
    return 0
  fi

  local ipv4 ipv6 cname mx txt ns ttl
  # Cache por registro.
  ipv4="$(dns::_cached A "${host}")"
  ipv6="$(dns::_cached AAAA "${host}")"
  cname="$(dns::_cached CNAME "${host}")"
  ns="$(dns::_cached NS "${host}")"
  mx="$(dns::_cached MX "${host}")"
  txt="$(dns::_cached TXT "${host}")"

  if utils::has dig; then
    ttl="$(dns::_dig_ttl A "${host}")"
  fi

  t1="$(dns::_millis)"
  elapsed="$(dns::_delta "${t0}" "${t1}")"

  utils::result_set dns.ipv4 "${ipv4}"
  utils::result_set dns.ipv6 "${ipv6}"
  utils::result_set dns.cname "${cname}"
  utils::result_set dns.ns "$(printf '%s' "${ns}" | tr '\n' ' ' | utils::trim)"
  utils::result_set dns.mx "$(printf '%s' "${mx}" | tr '\n' ' ' | utils::trim)"
  utils::result_set dns.txt_count "$(printf '%s' "${txt}" | grep -c . || true)"
  utils::result_set dns.ttl "${ttl:-}"
  utils::result_set dns.time_ms "${elapsed}"

  # PTR / Reverse do primeiro IPv4.
  local first_ip; first_ip="$(printf '%s' "${ipv4}" | head -n1)"
  if [[ -n "${first_ip}" ]]; then
    local ptr; ptr="$(dns::reverse "${first_ip}")"
    utils::result_set dns.ptr "${ptr}"
  fi

  # Detecção de CDN a partir de CNAME + NS + PTR.
  local cdn
  cdn="$(dns::detect_cdn "${cname} ${ns} ${ptr:-}")"
  utils::result_set dns.cdn "${cdn}"

  # Estado geral.
  if [[ -n "${ipv4}" || -n "${ipv6}" ]]; then
    utils::result_set dns.status "OK"
  else
    utils::result_set dns.status "CRITICAL"
    utils::warn "DNS: nenhum registro A/AAAA para ${host}"
  fi
}

# dns::_cached <tipo> <host> - wrapper com cache (TTL 300s).
dns::_cached() {
  local rtype="$1" host="$2" out
  if out="$(utils::cache_get dns "${rtype}:${host}")"; then
    printf '%s' "${out}"
    return 0
  fi
  out="$(dns::query "${rtype}" "${host}")"
  utils::cache_set dns "${rtype}:${host}" 300 "${out}"
  printf '%s' "${out}"
}

# dns::reverse <ip> - PTR/reverse DNS.
dns::reverse() {
  local ip="$1"
  if utils::has dig; then
    dig +short -x "${ip}" 2>/dev/null | head -n1 | sed 's/\.$//'
  elif utils::has host; then
    host "${ip}" 2>/dev/null | awk '/pointer/{print $NF}' | head -n1 | sed 's/\.$//'
  fi
}

# dns::_millis / dns::_delta - medição de tempo portável (ms).
dns::_millis() {
  # date +%s%N não existe no macOS; usa fallback com perl/python? Não.
  # Estratégia: no Linux usa %s%N; em outros, usa segundos (resolução menor).
  if [[ "${WEBAUDIT_OS}" == "linux" ]]; then
    date +%s%3N
  else
    printf '%s000' "$(date +%s)"
  fi
}

dns::_delta() {
  local a="$1" b="$2"
  printf '%s' "$(( b - a ))"
}
