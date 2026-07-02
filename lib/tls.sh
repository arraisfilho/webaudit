#!/usr/bin/env bash
#
# tls.sh - Análise da camada TLS via openssl s_client.
#
# Responsabilidade única: determinar quais versões de TLS o servidor aceita,
# a versão/cipher negociados, ALPN, forward secrecy, compressão, reuso de
# sessão, session tickets e OCSP stapling / Must-Staple.
#
# Guarda o output completo do handshake TLS 1.3/1.2 em WEBAUDIT_TLS_DUMP para
# ser reaproveitado pelo módulo cert (evita novo handshake).
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_TLS_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_TLS_LOADED=1

WEBAUDIT_TLS_DUMP=""

# tls::_connect <host> <porta> <flags...> - executa s_client capturando saída.
# Envia "Q\n" no stdin para encerrar limpo.
tls::_connect() {
  local host="$1" port="$2"; shift 2
  printf 'Q\n' | utils::run_timeout "${WEBAUDIT_TIMEOUT}" \
	    openssl s_client -connect "${host}:${port}" -servername "${host}" "$@" 2>/dev/null || true
}

tls::_contains_i() {
  local haystack needle
  haystack="$(printf '%s' "$1" | utils::lower)"
  needle="$(printf '%s' "$2" | utils::lower)"
  [[ "${haystack}" == *"${needle}"* ]]
}

# tls::_supports <host> <porta> <flag_versao> - testa se uma versão TLS conecta.
tls::_supports() {
  local host="$1" port="$2" flag="$3"
  local out
  out="$(tls::_connect "${host}" "${port}" "${flag}")"
  if [[ "${out}" == *"BEGIN CERTIFICATE"* || "${out}" == *"New, TLS"* ]]; then
    return 0
  fi
  return 1
}

# tls::run <host> - orquestra a análise TLS.
tls::run() {
  local host="$1" port="${WEBAUDIT_PORT_HTTPS}"
  utils::debug "TLS: analisando ${host}:${port}"

  # Detecta flags de versão suportadas pelo openssl local.
  local has_tls13=0
  openssl s_client -help 2>&1 | grep -q -- '-tls1_3' && has_tls13=1

  # --- Suporte por versão --- (registra Sim/Nao via helper explícito)
  tls::_record_support() {
    local key="$1"; shift
    if tls::_supports "$@"; then utils::result_set "${key}" "Sim"
    else utils::result_set "${key}" "Nao"; fi
  }
  tls::_record_support tls.v10 "${host}" "${port}" -tls1
  tls::_record_support tls.v11 "${host}" "${port}" -tls1_1
  tls::_record_support tls.v12 "${host}" "${port}" -tls1_2
  if [[ "${has_tls13}" == "1" ]]; then
    tls::_record_support tls.v13 "${host}" "${port}" -tls1_3
  else
    utils::result_set tls.v13 "desconhecido (openssl sem TLS1.3)"
  fi

  # --- Handshake padrão (com ALPN e status OCSP) para coletar detalhes ---
  WEBAUDIT_TLS_DUMP="$(tls::_connect "${host}" "${port}" -alpn 'h2,http/1.1' -status -tlsextdebug)"
  export WEBAUDIT_TLS_DUMP

  # Versão negociada. Preferimos o bloco "SSL-Session:" (Protocol :); se
  # ausente (alguns servidores/proxies não o emitem), usamos a linha
  # "New, TLSvX.Y, Cipher is ...".
  local negver
  negver="$(printf '%s' "${WEBAUDIT_TLS_DUMP}" | awk -F': ' '/Protocol *:/{print $2}' | head -n1 | utils::trim)"
  if [[ -z "${negver}" ]]; then
    negver="$(printf '%s' "${WEBAUDIT_TLS_DUMP}" \
      | sed -n 's/^New, \(TLSv[0-9.]*\).*/\1/p' | head -n1 | utils::trim)"
  fi
  utils::result_set tls.negotiated "${negver:-desconhecido}"

  # Cipher negociado (bloco SSL-Session ou linha "New, ..., Cipher is X").
  local cipher
  cipher="$(printf '%s' "${WEBAUDIT_TLS_DUMP}" | awk -F': ' '/Cipher *:/{print $2}' | head -n1 | utils::trim)"
  if [[ -z "${cipher}" ]]; then
    cipher="$(printf '%s' "${WEBAUDIT_TLS_DUMP}" \
      | sed -n 's/^New, .*Cipher is \([^ ]*\).*/\1/p' | head -n1 | utils::trim)"
  fi
  # Descarta linha "Cipher is (NONE)".
  [[ "${cipher}" == *NONE* ]] && cipher=""
  utils::result_set tls.cipher "${cipher:-desconhecido}"

  # ALPN.
  local alpn
  alpn="$(printf '%s' "${WEBAUDIT_TLS_DUMP}" | awk -F': ' '/ALPN protocol/{print $2}' | head -n1 | utils::trim)"
  utils::result_set tls.alpn "${alpn:-nenhum}"

  # Forward secrecy (ECDHE/DHE no cipher ou TLS 1.3).
  if [[ "${negver}" == "TLSv1.3" ]] || printf '%s' "${cipher}" | grep -qiE 'ECDHE|DHE'; then
    utils::result_set tls.forward_secrecy "Sim"
  else
    utils::result_set tls.forward_secrecy "Nao"
  fi

  # Compressão TLS (deve ser NONE).
  local compq
  compq="$(printf '%s' "${WEBAUDIT_TLS_DUMP}" | awk -F': ' '/Compression *:/{print $2}' | head -n1 | utils::trim)"
  utils::result_set tls.compression "${compq:-NONE}"

  # Session tickets / reuse.
  if printf '%s' "${WEBAUDIT_TLS_DUMP}" | grep -qiE 'TLS session ticket:'; then
    utils::result_set tls.session_ticket "Sim"
  else
    utils::result_set tls.session_ticket "Nao"
  fi
  tls::_check_reuse "${host}" "${port}"

  # OCSP stapling.
  if printf '%s' "${WEBAUDIT_TLS_DUMP}" | grep -qiE 'OCSP Response Status: successful'; then
    utils::result_set tls.ocsp_stapling "Sim"
  elif printf '%s' "${WEBAUDIT_TLS_DUMP}" | grep -qiE 'OCSP response: *no response sent'; then
    utils::result_set tls.ocsp_stapling "Nao"
  else
    utils::result_set tls.ocsp_stapling "Nao"
  fi

  # OCSP Must-Staple (extensão TLS Feature status_request no cert).
  if printf '%s' "${WEBAUDIT_TLS_DUMP}" | grep -qiE 'status_request|TLS Feature'; then
    utils::result_set tls.ocsp_must_staple "Sim"
  else
    utils::result_set tls.ocsp_must_staple "Nao"
  fi

  # Estado geral: crítico se TLS1.0/1.1 habilitados; warning se sem 1.3.
  if [[ "$(utils::result_get tls.v10)" == "Sim" || "$(utils::result_get tls.v11)" == "Sim" ]]; then
    utils::result_set tls.rating "WARNING"
  elif [[ "$(utils::result_get tls.v13)" == "Sim" ]]; then
    utils::result_set tls.rating "OK"
  else
    utils::result_set tls.rating "OK"
  fi
}

# tls::_check_reuse <host> <porta> - testa reuso de sessão com -reconnect.
tls::_check_reuse() {
  local host="$1" port="$2" out
  out="$(printf 'Q\n' | utils::run_timeout "${WEBAUDIT_TIMEOUT}" \
    openssl s_client -connect "${host}:${port}" -servername "${host}" -reconnect 2>/dev/null || true)"
  if tls::_contains_i "${out}" "Reused"; then
    utils::result_set tls.session_reuse "Sim"
  else
    utils::result_set tls.session_reuse "Nao"
  fi
}
