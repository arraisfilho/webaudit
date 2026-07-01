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

# report::_row <rotulo> <valor> [cor] - imprime linha "rotulo.... valor".
report::_row() {
  local label="$1" value="$2" color="${3:-}"
  local pad
  # Preenche com pontos até 16 colunas de rótulo.
  printf -v pad '%-16s' "${label}"
  pad="${pad// /.}"
  if [[ -n "${color}" ]]; then
    printf '%s %b%s%b\n' "${pad}" "${color}" "${value}" "${C_RESET}"
  else
    printf '%s %s\n' "${pad}" "${value}"
  fi
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

# report::text <host> <elapsed> - renderiza o relatório de terminal.
report::text() {
  local host="$1" elapsed="$2"
  local line='══════════════════════════════════════════════'

  # Modo quiet: apenas a nota geral.
  if [[ "${WEBAUDIT_QUIET}" == "1" ]]; then
    local overall; overall="$(report::overall)"
    printf '%b%s%b %s\n' "$(report::_color_for "${overall}")" "${overall}" "${C_RESET}" "${host}"
    return 0
  fi

  printf '%b%s%b\n\n' "${C_CYAN}" "${line}" "${C_RESET}"

  report::_row "Host" "${host}"
  report::_row "IPv4" "$(utils::result_get dns.ipv4 | tr '\n' ' ' | utils::trim)"
  report::_row "IPv6" "$(utils::result_get dns.ipv6 | tr '\n' ' ' | utils::trim)"
  [[ -n "$(utils::result_get dns.cdn)" ]] && report::_row "CDN" "$(utils::result_get dns.cdn)"
  printf '\n'

  report::_row "HTTP" "$(utils::result_get http.status)" "$(report::_color_for "$(utils::result_get http.status)")"
  report::_row "HTTPS" "$(utils::result_get https.status)" "$(report::_color_for "$(utils::result_get https.status)")"
  printf '\n'

  report::_row "TLS" "$(utils::result_get tls.negotiated)"
  report::_row "Cipher" "$(utils::result_get tls.cipher)"
  printf '\n'

  local cs; cs="$(utils::result_get cert.status)"
  report::_row "Certificado" "${cs}" "$(report::_color_for "${cs}")"
  report::_row "Emissor" "$(utils::result_get cert.issuer_org)"
  report::_row "Algoritmo" "$(utils::result_get cert.key_type)$(utils::result_get cert.key_bits)"
  report::_row "Expira em" "$(utils::result_get cert.days_left) dias"
  printf '\n'

  report::_row "Servidor" "$(utils::result_get server.software)"
  report::_row "Versao" "$(utils::result_get server.version)"
  report::_row "Sistema" "$(utils::result_get server.os)"
  if [[ "$(utils::result_get server.masked)" == "Sim" ]]; then
    report::_row "Fingerprint" "$(utils::result_get fingerprint.guess) (conf: $(utils::result_get fingerprint.confidence))"
  fi
  printf '\n'

  report::_row "HTTP/2" "$(utils::result_get http.http2)"
  report::_row "HTTP/3" "$(utils::result_get http.http3)"
  printf '\n'

  local hsts_state csp_state
  [[ "$(utils::result_get sec.hsts)" == "Ausente" ]] && hsts_state="Ausente" || hsts_state="OK"
  [[ "$(utils::result_get sec.csp)" == "Ausente" ]] && csp_state="Ausente" || csp_state="OK"
  report::_row "HSTS" "${hsts_state}" "$(report::_color_for "$( [[ ${hsts_state} == OK ]] && echo OK || echo WARNING )")"
  report::_row "CSP" "${csp_state}" "$(report::_color_for "$( [[ ${csp_state} == OK ]] && echo OK || echo WARNING )")"
  report::_row "Seguranca" "$(utils::result_get sec.score)"
  printf '\n'

  report::_row "Ultima versao" "$(utils::result_get version.latest)"
  report::_row "Status" "$(utils::result_get version.status)"
  printf '\n'

  report::_row "CVEs" "$(utils::result_get cve.status)"
  printf '\n'

  report::_row "Tempo" "${elapsed} segundos"
  printf '\n'

  # Detalhes extras em modo verbose.
  if [[ "${WEBAUDIT_VERBOSE}" == "1" ]]; then
    report::_verbose_block
  fi

  printf '%b%s%b\n' "${C_CYAN}" "${line}" "${C_RESET}"
}

# report::_verbose_block - despeja todos os campos coletados.
report::_verbose_block() {
  printf '%b--- Detalhes (verbose) ---%b\n' "${C_GRAY}" "${C_RESET}"
  local k
  for k in "${WEBAUDIT_RESULT_ORDER[@]}"; do
    printf '%b%-26s%b %s\n' "${C_GRAY}" "${k}" "${C_RESET}" "${WEBAUDIT_RESULT[$k]}"
  done
  # Lista de CVEs, se houver.
  if utils::result_has cve.list; then
    printf '\n%bCVEs:%b\n' "${C_YELLOW}" "${C_RESET}"
    printf '%s\n' "$(utils::result_get cve.list)"
  fi
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
    v="${WEBAUDIT_RESULT[$k]}"
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
