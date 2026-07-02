#!/usr/bin/env bash
#
# report.sh - Renderização do relatório em texto e dispatcher de formatos.
#
# Responsabilidades:
#   - report::text  : saída legível no terminal (o "relatório" do enunciado).
#   - report::yaml  : saída YAML (formato --yaml).
#   - report::emit  : escolhe o renderer conforme WEBAUDIT_OUTPUT.
#   - report::status_code : converte a nota geral em exit code.
#
# Os formatos json/csv/html/markdown ficam nos módulos homônimos.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_REPORT_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_REPORT_LOADED=1

# report::_clean_value <valor> [fallback] - valor de exibição de uma linha.
report::_clean_value() {
  local value="$1" fallback="${2:--}"
  value="$(printf '%s' "${value}" | tr '\n' ' ' | utils::trim)"
  [[ -n "${value}" ]] || value="${fallback}"
  printf '%s' "${value}"
}

# report::_section <titulo> - cabeçalho visual de uma seção.
report::_section() {
  printf '%b%s%b\n' "${C_BOLD}" "$1" "${C_RESET}"
}

# report::_row <rotulo> <valor> [estado] - imprime linha alinhada.
report::_row() {
  local label="$1" value="$2" state="${3:-}" color=""
  value="$(report::_clean_value "${value}")"
  [[ -n "${state}" ]] && color="$(report::_color_for "${state}")"

  printf '  %-20s ' "${label}"
  if [[ -n "${color}" ]]; then
    printf '%b%s%b\n' "${color}" "${value}" "${C_RESET}"
  else
    printf '%s\n' "${value}"
  fi
}

# report::_row_key <rotulo> <chave> [estado] - linha a partir do result store.
report::_row_key() {
  local label="$1" key="$2" state="${3:-}"
  report::_row "${label}" "$(utils::result_get "${key}")" "${state}"
}

# report::_color_for <estado> - mapeia OK/WARNING/CRITICAL para cor.
report::_color_for() {
  case "$1" in
    OK)       printf '%s' "${C_GREEN}" ;;
    WARNING)  printf '%s' "${C_YELLOW}" ;;
    CRITICAL) printf '%s' "${C_RED}" ;;
    *)        printf '%s' "${C_GRAY}" ;;
  esac
}

# report::_severity_color <severidade> - cor para severidade de CVE.
report::_severity_color() {
  case "$1" in
    CRITICAL|HIGH) printf '%s' "${C_RED}" ;;
    MEDIUM)        printf '%s' "${C_YELLOW}" ;;
    LOW)           printf '%s' "${C_GREEN}" ;;
    *)             printf '%s' "${C_GRAY}" ;;
  esac
}

# report::_presence_state <valor> - OK quando presente, WARNING quando ausente.
report::_presence_state() {
  local value="$1"
  if [[ -z "${value}" || "${value}" == "Ausente" ]]; then
    printf 'WARNING'
  else
    printf 'OK'
  fi
}

# report::_version_state <valor> - heurística de cor para status de versão.
report::_version_state() {
  case "$1" in
    Atualizado)                 printf 'OK' ;;
    *recomendada*|*mascarada*)  printf 'WARNING' ;;
    *)                          printf '' ;;
  esac
}

# report::_key_summary - imprime uma descrição legível da chave do certificado.
report::_key_summary() {
  local key_type key_bits
  key_type="$(utils::result_get cert.key_type)"
  key_bits="$(utils::result_get cert.key_bits)"
  if [[ -n "${key_type}" && -n "${key_bits}" ]]; then
    printf '%s %s bits' "${key_type}" "${key_bits}"
  else
    report::_clean_value "${key_type}${key_bits}"
  fi
}

# report::_days_summary - imprime validade do certificado.
report::_days_summary() {
  local days
  days="$(utils::result_get cert.days_left)"
  if [[ "${days}" =~ ^-?[0-9]+$ ]]; then
    printf '%s dias' "${days}"
  else
    report::_clean_value "${days}"
  fi
}

# report::_cve_table - tabela compacta de CVEs no terminal.
report::_cve_table() {
  local line id cvss severity published url color
  printf '  %-16s %-10s %-10s %-12s %s\n' "ID" "CVSS" "Severidade" "Data" "Link"
  while IFS=$'\t' read -r id cvss severity published url; do
    [[ -n "${id}" ]] || continue
    color="$(report::_severity_color "${severity}")"
    printf '  %-16s %-10s ' "${id}" "$(report::_clean_value "${cvss}")"
    printf '%b%-10s%b ' "${color}" "$(report::_clean_value "${severity}")" "${C_RESET}"
    printf '%-12s %s\n' \
      "$(report::_clean_value "${published}")" \
      "$(report::_clean_value "${url}")"
  done <<<"$(utils::result_get cve.list)"
}

# report::text <host> <elapsed> - renderiza o relatório de terminal.
report::text() {
  local host="$1" elapsed="$2"
  local line='────────────────────────────────────────────────────────────'

  # Modo quiet: apenas a nota geral.
  if [[ "${WEBAUDIT_QUIET:-0}" == "1" ]]; then
    local overall; overall="$(report::overall)"
    printf '%b%s%b %s\n' "$(report::_color_for "${overall}")" "${overall}" "${C_RESET}" "${host}"
    return 0
  fi

  local overall; overall="$(report::overall)"

  printf '%b%s%b\n' "${C_CYAN}" "${line}" "${C_RESET}"
  printf '%bWebAudit%b  %s  ' "${C_BOLD}" "${C_RESET}" "${host}"
  printf '%b%s%b\n' "$(report::_color_for "${overall}")" "${overall}" "${C_RESET}"
  printf '%b%s%b\n\n' "${C_CYAN}" "${line}" "${C_RESET}"

  report::_section "Rede"
  report::_row "Host" "${host}"
  report::_row_key "IPv4" dns.ipv4
  report::_row_key "IPv6" dns.ipv6
  report::_row_key "CDN" dns.cdn
  report::_row_key "DNS" dns.status "$(utils::result_get dns.status)"
  printf '\n'

  report::_section "Disponibilidade"
  report::_row_key "HTTP" http.status "$(utils::result_get http.status)"
  report::_row_key "Codigo HTTP" http.code
  report::_row_key "HTTPS" https.status "$(utils::result_get https.status)"
  report::_row_key "Codigo HTTPS" https.code
  report::_row_key "Redirects HTTPS" https.redirects
  report::_row_key "Loop redirect" http.redirect_loop
  printf '\n'

  report::_section "TLS e certificado"
  local cert_status
  cert_status="$(utils::result_get cert.status)"
  report::_row_key "TLS" tls.negotiated
  report::_row_key "Cipher" tls.cipher
  report::_row_key "ALPN" tls.alpn
  report::_row_key "Forward secrecy" tls.forward_secrecy
  report::_row "Certificado" "${cert_status}" "${cert_status}"
  report::_row_key "Emissor" cert.issuer_org
  report::_row "Chave" "$(report::_key_summary)"
  report::_row "Expira em" "$(report::_days_summary)"
  report::_row_key "Hostname valido" cert.hostname_valid
  printf '\n'

  report::_section "Servidor"
  report::_row_key "Software" server.software
  report::_row_key "Versao" server.version
  report::_row_key "Sistema" server.os
  report::_row_key "HTTP/2" http.http2
  report::_row_key "HTTP/3" http.http3
  if [[ "$(utils::result_get server.masked)" == "Sim" || -n "$(utils::result_get fingerprint.guess)" ]]; then
    report::_row "Fingerprint" "$(utils::result_get fingerprint.guess) (conf: $(utils::result_get fingerprint.confidence))"
  fi
  printf '\n'

  report::_section "Seguranca"
  local hsts csp version_status
  hsts="$(utils::result_get sec.hsts)"
  csp="$(utils::result_get sec.csp)"
  version_status="$(utils::result_get version.status)"
  report::_row "HSTS" "${hsts}" "$(report::_presence_state "${hsts}")"
  report::_row "CSP" "${csp}" "$(report::_presence_state "${csp}")"
  report::_row_key "X-Frame-Options" sec.xfo "$(report::_presence_state "$(utils::result_get sec.xfo)")"
  report::_row_key "Referrer-Policy" sec.referrer "$(report::_presence_state "$(utils::result_get sec.referrer)")"
  report::_row_key "Pontuacao" sec.score
  report::_row_key "Ultima versao" version.latest
  report::_row "Status versao" "${version_status}" "$(report::_version_state "${version_status}")"
  printf '\n'

  report::_section "Vulnerabilidades"
  report::_row_key "CVEs" cve.status
  if utils::result_has cve.list; then
    report::_cve_table
  fi
  printf '\n'

  report::_section "Execucao"
  report::_row "Tempo" "${elapsed} segundos"
  printf '\n'

  # Detalhes extras em modo verbose.
  if [[ "${WEBAUDIT_VERBOSE:-0}" == "1" ]]; then
    report::_verbose_block
  fi

  printf '%b%s%b\n' "${C_CYAN}" "${line}" "${C_RESET}"
}

# report::_verbose_block - despeja todos os campos coletados.
report::_verbose_block() {
  printf '%b--- Detalhes (verbose) ---%b\n' "${C_GRAY}" "${C_RESET}"
  local k
  for k in "${WEBAUDIT_RESULT_ORDER[@]}"; do
    printf '%b%-26s%b %s\n' "${C_GRAY}" "${k}" "${C_RESET}" "$(utils::result_get "${k}")"
  done
  printf '\n'
}

# report::overall - nota geral combinando os subsistemas.
report::overall() {
  local worst="OK" s
  for s in "$(utils::result_get dns.status)" "$(utils::result_get tcp.status)" \
           "$(utils::result_get https.status)" "$(utils::result_get cert.status)" \
           "$(utils::result_get tls.rating)" "$(utils::result_get sec.rating)"; do
    case "${s}" in
      CRITICAL) worst="CRITICAL" ;;
      WARNING)  [[ "${worst}" != "CRITICAL" ]] && worst="WARNING" ;;
    esac
  done
  printf '%s' "${worst}"
}

# report::status_code - exit code a partir da nota geral.
report::status_code() {
  case "$(report::overall)" in
    OK)       printf '0' ;;
    WARNING)  printf '1' ;;
    CRITICAL) printf '2' ;;
    *)        printf '3' ;;
  esac
}

# report::yaml <host> <elapsed> - saída YAML de um host.
report::yaml() {
  local host="$1" elapsed="$2" k v
  printf -- '- host: "%s"\n' "${host}"
  printf '  elapsed_seconds: %s\n' "${elapsed}"
  printf '  overall: %s\n' "$(report::overall)"
  printf '  results:\n'
  for k in "${WEBAUDIT_RESULT_ORDER[@]}"; do
    v="$(utils::result_get "${k}")"
    # Escapa aspas e quebras de linha para escalar YAML seguro.
    v="${v//\"/\\\"}"
    v="${v//$'\n'/ }"
    printf '    %s: "%s"\n' "${k}" "${v}"
  done
}

# report::emit <host> <elapsed> - dispatcher por formato.
report::emit() {
  local host="$1" elapsed="$2"
  case "${WEBAUDIT_OUTPUT}" in
    text)     report::text "${host}" "${elapsed}" ;;
    yaml)     report::yaml "${host}" "${elapsed}" ;;
    json)     json::emit "${host}" "${elapsed}" ;;
    csv)      csv::emit "${host}" "${elapsed}" ;;
    html)     html::emit "${host}" "${elapsed}" ;;
    markdown) markdown::emit "${host}" "${elapsed}" ;;
    *)        report::text "${host}" "${elapsed}" ;;
  esac
}
