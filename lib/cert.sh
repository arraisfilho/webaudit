#!/usr/bin/env bash
#
# cert.sh - Análise do certificado X.509 do servidor.
#
# Responsabilidade única: extrair e validar os dados do certificado apresentado
# no handshake TLS: subject, issuer, organização, CN, SAN, wildcard, serial,
# fingerprints (SHA1/SHA256), tipo/tamanho de chave, algoritmo de assinatura,
# validade (notBefore/notAfter/dias restantes), autoassinado, verify code,
# cadeia completa e verificação de hostname.
#
# Reaproveita WEBAUDIT_TLS_DUMP quando presente; caso contrário, faz um novo
# handshake com -showcerts.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_CERT_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_CERT_LOADED=1

WEBAUDIT_CERT_PEM=""

# cert::_fetch <host> <porta> - obtém dump com -showcerts (para a cadeia) e o
# certificado folha em PEM (WEBAUDIT_CERT_PEM).
cert::_fetch() {
  local host="$1" port="$2"
  local dump
  dump="$(printf 'Q\n' | utils::run_timeout "${WEBAUDIT_TIMEOUT}" \
    openssl s_client -connect "${host}:${port}" -servername "${host}" \
    -showcerts 2>/dev/null || true)"
  printf '%s' "${dump}"
}

# cert::_leaf_pem <dump> - extrai o primeiro certificado PEM do dump.
cert::_leaf_pem() {
  awk '/-----BEGIN CERTIFICATE-----/{c++} c==1{print} /-----END CERTIFICATE-----/{if(c==1) exit}'
}

# cert::_x509 <campo> - roda openssl x509 sobre WEBAUDIT_CERT_PEM.
cert::_x509() {
  printf '%s' "${WEBAUDIT_CERT_PEM}" | openssl x509 -noout "$@" 2>/dev/null || true
}

# cert::run <host> - orquestra a análise de certificado.
cert::run() {
  local host="$1" port="${WEBAUDIT_PORT_HTTPS}"
  utils::debug "CERT: analisando certificado de ${host}"

  local dump
  dump="$(cert::_fetch "${host}" "${port}")"
  if [[ -z "${dump}" ]]; then
    utils::result_set cert.status "CRITICAL"
    utils::warn "CERT: nao foi possivel obter certificado de ${host}"
    return 0
  fi

  WEBAUDIT_CERT_PEM="$(printf '%s' "${dump}" | cert::_leaf_pem)"
  export WEBAUDIT_CERT_PEM

  # Subject / Issuer.
  local subject issuer
  subject="$(cert::_x509 -subject | sed 's/^subject=//' | utils::trim)"
  issuer="$(cert::_x509 -issuer | sed 's/^issuer=//' | utils::trim)"
  utils::result_set cert.subject "${subject}"
  utils::result_set cert.issuer "${issuer}"

  # Common Name e Organization (issuer).
  utils::result_set cert.cn "$(cert::_field "${subject}" 'CN')"
  utils::result_set cert.issuer_org "$(cert::_field "${issuer}" 'O')"
  utils::result_set cert.issuer_cn "$(cert::_field "${issuer}" 'CN')"

  # SAN + wildcard.
  local san
  san="$(cert::_x509 -ext subjectAltName 2>/dev/null | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr '\n' ' ' | utils::trim)"
  [[ -z "${san}" ]] && san="$(printf '%s' "${WEBAUDIT_CERT_PEM}" | openssl x509 -noout -text 2>/dev/null | awk '/Subject Alternative Name/{getline; print}' | tr ',' '\n' | grep -oE 'DNS:[^ ]+' | sed 's/DNS://g' | tr '\n' ' ' | utils::trim)"
  utils::result_set cert.san "${san}"
  if printf '%s' "${san}" | grep -q '\*\.'; then
    utils::result_set cert.wildcard "Sim"
  else
    utils::result_set cert.wildcard "Nao"
  fi

  # Serial.
  utils::result_set cert.serial "$(cert::_x509 -serial | sed 's/^serial=//')"

  # Fingerprints.
  utils::result_set cert.sha1 "$(cert::_x509 -fingerprint -sha1 | sed 's/^.*=//')"
  utils::result_set cert.sha256 "$(cert::_x509 -fingerprint -sha256 | sed 's/^.*=//')"

  # Tipo e tamanho de chave.
  cert::_key_info

  # Algoritmo de assinatura.
  local sigalg
  sigalg="$(printf '%s' "${WEBAUDIT_CERT_PEM}" | openssl x509 -noout -text 2>/dev/null \
             | awk -F': ' '/Signature Algorithm/{print $2; exit}' | utils::trim)"
  utils::result_set cert.sig_alg "${sigalg}"

  # Validade.
  cert::_validity

  # Autoassinado.
  if [[ "${subject}" == "${issuer}" ]]; then
    utils::result_set cert.self_signed "Sim"
  else
    utils::result_set cert.self_signed "Nao"
  fi

  # Verify return code (a partir do dump).
  local vrc
  vrc="$(printf '%s' "${dump}" | awk -F': ' '/Verify return code/{print $2}' | head -n1 | utils::trim)"
  utils::result_set cert.verify_code "${vrc:-desconhecido}"

  # Cadeia: conta certificados e identifica emissores.
  local chain_count
  chain_count="$(printf '%s' "${dump}" | grep -c 'BEGIN CERTIFICATE' || true)"
  utils::result_set cert.chain_count "${chain_count}"

  # Verificação de hostname.
  cert::_verify_hostname "${host}"

  # Estado geral do certificado.
  cert::_rate
}

# cert::_field <dn> <campo> - extrai um RDN (ex.: CN, O) de um DN openssl.
cert::_field() {
  local dn="$1" key="$2"
  # Formato moderno: "CN = exemplo.com, O = ..." ou legado "/CN=.../O=...".
  printf '%s' "${dn}" \
    | grep -oE "${key} *= *[^,/]+" \
    | head -n1 | sed -E "s/${key} *= *//" | utils::trim
}

# cert::_key_info - determina RSA/ECDSA/Ed25519 e tamanho.
cert::_key_info() {
  local text
  text="$(printf '%s' "${WEBAUDIT_CERT_PEM}" | openssl x509 -noout -text 2>/dev/null)"
  local algo bits
  if printf '%s' "${text}" | grep -qi 'Public Key Algorithm: id-ecPublicKey\|Public Key Algorithm: EC'; then
    algo="ECDSA"
    bits="$(printf '%s' "${text}" | grep -oE '\([0-9]+ bit\)' | head -n1 | grep -oE '[0-9]+')"
  elif printf '%s' "${text}" | grep -qi 'ED25519'; then
    algo="Ed25519"; bits="256"
  elif printf '%s' "${text}" | grep -qi 'rsaEncryption'; then
    algo="RSA"
    bits="$(printf '%s' "${text}" | grep -oE 'Public-Key: \([0-9]+ bit\)' | grep -oE '[0-9]+')"
  else
    algo="desconhecido"; bits=""
  fi
  utils::result_set cert.key_type "${algo}"
  utils::result_set cert.key_bits "${bits}"
}

# cert::_validity - notBefore/notAfter/dias restantes.
cert::_validity() {
  local nb na
  nb="$(cert::_x509 -startdate | sed 's/^notBefore=//' | utils::trim)"
  na="$(cert::_x509 -enddate | sed 's/^notAfter=//' | utils::trim)"
  utils::result_set cert.not_before "${nb}"
  utils::result_set cert.not_after "${na}"

  local na_epoch now days
  na_epoch="$(utils::epoch "${na}")"
  now="$(utils::now_epoch)"
  if [[ "${na_epoch}" =~ ^[0-9]+$ ]]; then
    days="$(( (na_epoch - now) / 86400 ))"
    utils::result_set cert.days_left "${days}"
    if (( days < 0 )); then
      utils::result_set cert.expired "Sim"
    else
      utils::result_set cert.expired "Nao"
    fi
  else
    utils::result_set cert.days_left "desconhecido"
    utils::result_set cert.expired "desconhecido"
  fi
}

# cert::_verify_hostname <host> - confere se o host casa com CN/SAN.
cert::_verify_hostname() {
  local host="$1"
  local match
  match="$(printf '%s' "${WEBAUDIT_CERT_PEM}" \
    | openssl x509 -noout -checkhost "${host}" 2>/dev/null || true)"
  if printf '%s' "${match}" | grep -qi 'does match'; then
    utils::result_set cert.hostname_valid "Sim"
  elif [[ -n "${match}" ]]; then
    utils::result_set cert.hostname_valid "Nao"
  else
    # Fallback manual: compara com SAN/CN considerando wildcard.
    if cert::_manual_hostmatch "${host}"; then
      utils::result_set cert.hostname_valid "Sim"
    else
      utils::result_set cert.hostname_valid "Nao"
    fi
  fi
}

cert::_manual_hostmatch() {
  local host="$1" name
  local san cn
  san="$(utils::result_get cert.san)"
  cn="$(utils::result_get cert.cn)"
  for name in ${san} ${cn}; do
    if [[ "${name}" == "${host}" ]]; then return 0; fi
    if [[ "${name}" == '*.'* ]]; then
      local suffix="${name#\*.}"
      [[ "${host}" == *".${suffix}" ]] && return 0
    fi
  done
  return 1
}

# cert::_rate - define cert.status combinando validade e hostname.
cert::_rate() {
  local days expired hostok self
  days="$(utils::result_get cert.days_left)"
  expired="$(utils::result_get cert.expired)"
  hostok="$(utils::result_get cert.hostname_valid)"
  self="$(utils::result_get cert.self_signed)"

  if [[ "${expired}" == "Sim" || "${hostok}" == "Nao" || "${self}" == "Sim" ]]; then
    utils::result_set cert.status "CRITICAL"
  elif [[ "${days}" =~ ^[0-9]+$ ]] && (( days < 15 )); then
    utils::result_set cert.status "WARNING"
  else
    utils::result_set cert.status "OK"
  fi
}
