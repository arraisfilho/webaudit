#!/usr/bin/env bash
#
# tcp.sh - Verificação de conectividade TCP.
#
# Responsabilidade única: testar abertura das portas HTTP/HTTPS, medir tempo
# de estabelecimento de conexão (handshake TCP) e detectar timeouts.
#
# Estratégia de portabilidade: usa /dev/tcp do bash (sempre disponível),
# medindo o tempo com SECONDS/date. `nc` é usado apenas como reforço opcional.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_TCP_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_TCP_LOADED=1

# tcp::connect <host> <porta> - tenta conexão TCP com timeout.
# Retorna 0 (aberta) / 1 (fechada/timeout). Imprime latência em ms no stdout.
tcp::connect() {
  local host="$1" port="$2"
  local t0 t1
  t0="$(tcp::_millis)"

  if tcp::_connect_dev_tcp "${host}" "${port}" || tcp::_connect_nc "${host}" "${port}"; then
    t1="$(tcp::_millis)"
    printf '%s' "$(( t1 - t0 ))"
    return 0
  fi
  printf ''
  return 1
}

tcp::_connect_dev_tcp() {
  local host="$1" port="$2"
  # Subshell com /dev/tcp; timeout aplicado externamente.
  utils::run_timeout "${WEBAUDIT_TIMEOUT}" bash -c \
    "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null
}

tcp::_connect_nc() {
  local host="$1" port="$2"
  utils::has nc || return 1

  # BSD/macOS nc usa -G para timeout de conexão; GNU/OpenBSD geralmente usa -w.
  nc -z -G "${WEBAUDIT_TIMEOUT}" "${host}" "${port}" >/dev/null 2>&1 && return 0
  nc -z -w "${WEBAUDIT_TIMEOUT}" "${host}" "${port}" >/dev/null 2>&1 && return 0
  return 1
}

# tcp::run <host> - executa os testes de porta.
tcp::run() {
  local host="$1"
  local ph="${WEBAUDIT_PORT_HTTP}" ps="${WEBAUDIT_PORT_HTTPS}"

  utils::debug "TCP: testando ${host}:${ph} e ${host}:${ps}"

  local lat_http lat_https
  if lat_http="$(tcp::connect "${host}" "${ph}")"; then
    utils::result_set tcp.http "OPEN"
    utils::result_set tcp.http_ms "${lat_http}"
  else
    utils::result_set tcp.http "CLOSED"
    utils::result_set tcp.http_ms ""
  fi

  if lat_https="$(tcp::connect "${host}" "${ps}")"; then
    utils::result_set tcp.https "OPEN"
    utils::result_set tcp.https_ms "${lat_https}"
  else
    utils::result_set tcp.https "CLOSED"
    utils::result_set tcp.https_ms ""
  fi

  if [[ "$(utils::result_get tcp.https)" == "OPEN" \
        || "$(utils::result_get tcp.http)" == "OPEN" ]]; then
    utils::result_set tcp.status "OK"
  else
    utils::result_set tcp.status "CRITICAL"
    utils::warn "TCP: nenhuma porta web acessível em ${host}"
  fi
}

tcp::_millis() {
  if [[ "${WEBAUDIT_OS}" == "linux" ]]; then
    date +%s%3N
  else
    printf '%s000' "$(date +%s)"
  fi
}
