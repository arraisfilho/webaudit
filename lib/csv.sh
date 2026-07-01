#!/usr/bin/env bash
#
# csv.sh - Saída em CSV (RFC 4180).
#
# Responsabilidade única: emitir uma linha CSV por host com um conjunto fixo
# de colunas (schema estável), adequado para planilhas e ingestão em BI.
# O cabeçalho é emitido pelo orquestrador (webaudit.sh) apenas uma vez.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_CSV_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_CSV_LOADED=1

# Colunas fixas do CSV (ordem estável).
WEBAUDIT_CSV_COLUMNS=(
  host overall
  dns.ipv4 dns.ipv6 dns.cdn
  http.status https.status https.code
  tls.negotiated tls.cipher
  cert.status cert.issuer_org cert.days_left cert.key_type cert.key_bits
  server.software server.version server.os
  http.http2 http.http3
  sec.hsts sec.csp sec.score
  version.latest version.status
  cve.count cve.status
  elapsed
)

# csv::header - imprime a linha de cabeçalho.
csv::header() {
  local col out=""
  for col in "${WEBAUDIT_CSV_COLUMNS[@]}"; do
    out+="${col},"
  done
  printf '%s\n' "${out%,}"
}

# csv::emit <host> <elapsed> - imprime a linha do host.
csv::emit() {
  local host="$1" elapsed="$2" col val out=""
  for col in "${WEBAUDIT_CSV_COLUMNS[@]}"; do
    case "${col}" in
      host)    val="${host}" ;;
      overall) val="$(report::overall)" ;;
      elapsed) val="${elapsed}" ;;
      *)       val="$(utils::result_get "${col}")" ;;
    esac
    # Normaliza quebras de linha em campos multivalor (ex.: IPs).
    val="${val//$'\n'/ }"
    out+="$(utils::csv_escape "${val}"),"
  done
  printf '%s\n' "${out%,}"
}
