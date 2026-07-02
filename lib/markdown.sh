#!/usr/bin/env bash
#
# markdown.sh - Saída em Markdown.
#
# Responsabilidade única: emitir um relatório Markdown por host, com tabelas
# por seção. No modo scanner, cada host gera sua própria seção (cabeçalho H2).
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_MARKDOWN_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_MARKDOWN_LOADED=1

# markdown::_row <rotulo> <chave> - linha de tabela a partir do result store.
markdown::_row() {
  local label="$1" key="$2" val
  val="$(utils::result_get "${key}")"
  val="${val//$'\n'/ }"
  val="$(printf '%s' "${val}" | utils::trim)"
  [[ -n "${val}" ]] || val="-"
  val="${val//|/\\|}"
  printf '| %s | %s |\n' "${label}" "${val}"
}

# markdown::emit <host> <elapsed>
markdown::emit() {
  local host="$1" elapsed="$2"

  printf '## %s\n\n' "${host}"
  printf '**Nota geral:** %s  \n' "$(report::overall)"
  printf '**Tempo:** %s s\n\n' "${elapsed}"

  printf '### Rede\n\n| Campo | Valor |\n|---|---|\n'
  markdown::_row "IPv4" dns.ipv4
  markdown::_row "IPv6" dns.ipv6
  markdown::_row "CDN" dns.cdn
  markdown::_row "HTTP" http.status
  markdown::_row "HTTPS" https.status
  printf '\n'

  printf '### TLS e Certificado\n\n| Campo | Valor |\n|---|---|\n'
  markdown::_row "TLS negociado" tls.negotiated
  markdown::_row "Cipher" tls.cipher
  markdown::_row "ALPN" tls.alpn
  markdown::_row "Forward Secrecy" tls.forward_secrecy
  markdown::_row "Certificado" cert.status
  markdown::_row "Emissor" cert.issuer_org
  markdown::_row "Chave" cert.key_type
  markdown::_row "Bits" cert.key_bits
  markdown::_row "Dias restantes" cert.days_left
  markdown::_row "Hostname valido" cert.hostname_valid
  printf '\n'

  printf '### Servidor\n\n| Campo | Valor |\n|---|---|\n'
  markdown::_row "Software" server.software
  markdown::_row "Versao" server.version
  markdown::_row "Sistema" server.os
  markdown::_row "Ultima versao" version.latest
  markdown::_row "Status versao" version.status
  markdown::_row "HTTP/2" http.http2
  markdown::_row "HTTP/3" http.http3
  printf '\n'

  printf '### Seguranca\n\n| Campo | Valor |\n|---|---|\n'
  markdown::_row "HSTS" sec.hsts
  markdown::_row "CSP" sec.csp
  markdown::_row "X-Content-Type-Options" sec.xcto
  markdown::_row "X-Frame-Options" sec.xfo
  markdown::_row "Referrer-Policy" sec.referrer
  markdown::_row "Pontuacao" sec.score
  printf '\n'

  printf '### Vulnerabilidades\n\n'
  printf '%s\n\n' "$(utils::result_get cve.status)"
  if utils::result_has cve.list; then
    printf '| ID | CVSS | Severidade | Data | Link |\n|---|---|---|---|---|\n'
    local IFS=$'\n' l
    while IFS= read -r l; do
      [[ -z "${l}" ]] && continue
      # Campos separados por tab.
      local id
      id="$(printf '%s' "${l}" | cut -f1)"
      printf '| %s | %s |\n' "${id}" "$(printf '%s' "${l}" | cut -f2- | tr '\t' '|')"
    done <<<"$(utils::result_get cve.list)"
    printf '\n'
  fi
}
