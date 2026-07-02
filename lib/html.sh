#!/usr/bin/env bash
#
# html.sh - Saída em HTML.
#
# Responsabilidade única: emitir um relatório HTML autocontido (CSS inline)
# por host. No modo scanner, os cartões de cada host são concatenados dentro
# de um único documento (o cabeçalho/rodapé são emitidos por webaudit.sh).
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_HTML_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_HTML_LOADED=1

# html::doc_header - abertura do documento (chamado uma vez).
html::doc_header() {
  cat <<'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebAudit - Relatorio</title>
<style>
  :root{--ok:#16833a;--warn:#b26a00;--crit:#d1242f;--bg:#f4f6f8;--panel:#fff;--fg:#111827;--mut:#667085;--br:#d9dee7;--accent:#155eef}
  *{box-sizing:border-box}
  body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:var(--bg);color:var(--fg);line-height:1.45}
  header{background:#111827;color:#fff;padding:22px 28px;border-bottom:4px solid var(--accent)}
  header h1{margin:0;font-size:22px;letter-spacing:0}
  header .sub{color:#cbd5e1;font-size:13px;margin-top:4px}
  main{max-width:1120px;margin:26px auto;padding:0 18px}
  .card{background:var(--panel);border:1px solid var(--br);border-radius:8px;margin-bottom:22px;overflow:hidden;box-shadow:0 10px 24px rgba(15,23,42,.07)}
  .card h2{margin:0;padding:16px 18px;border-bottom:1px solid var(--br);font-size:17px;display:flex;gap:12px;justify-content:space-between;align-items:center}
  .host{min-width:0;overflow-wrap:anywhere}
  .badge{font-size:12px;font-weight:700;padding:4px 10px;border-radius:999px;color:#fff;letter-spacing:0}
  .badge.OK{background:var(--ok)}.badge.WARNING{background:var(--warn)}.badge.CRITICAL{background:var(--crit)}
  .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0}
  .grid section:nth-child(odd){border-right:1px solid var(--br)}
  section{padding:16px 18px}
  section h3{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);margin:0 0 10px}
  table{width:100%;border-collapse:collapse;font-size:14px}
  td{padding:7px 0;vertical-align:top;border-top:1px solid #eef1f5}
  tr:first-child td{border-top:0}
  td.k{color:var(--mut);width:44%}
  td.v{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-word}
  .cve td{font-size:13px}
  footer{max-width:1120px;margin:0 auto 42px;padding:0 18px;color:var(--mut);font-size:12px}
  a{color:#0969da}
  @media (max-width:760px){
    header{padding:18px}
    main{margin:18px auto;padding:0 12px}
    .grid{grid-template-columns:1fr}
    .grid section:nth-child(odd){border-right:0;border-bottom:1px solid var(--br)}
    .card h2{align-items:flex-start;flex-direction:column}
  }
</style>
</head>
<body>
<header><h1>WebAudit</h1><div class="sub">Relatorio de auditoria HTTP/HTTPS/TLS</div></header>
<main>
EOF
}

# html::doc_footer - fechamento do documento (chamado uma vez).
html::doc_footer() {
  printf '</main>\n<footer>Gerado por WebAudit %s em %s</footer>\n</body>\n</html>\n' \
    "${WEBAUDIT_VERSION}" "$(utils::now_iso)"
}

# html::_kv <rotulo> <chave> - linha de tabela.
html::_kv() {
  local label="$1" key="$2" val
  val="$(utils::result_get "${key}" | tr '\n' ' ' | utils::trim)"
  [[ -n "${val}" ]] || val="-"
  val="$(utils::html_escape "${val}")"
  printf '<tr><td class="k">%s</td><td class="v">%s</td></tr>\n' "${label}" "${val}"
}

# html::emit <host> <elapsed> - cartão de um host.
html::emit() {
  local host="$1" elapsed="$2" overall
  overall="$(report::overall)"

  printf '<div class="card">\n'
  printf '<h2><span class="host">%s</span> <span class="badge %s">%s</span></h2>\n' \
    "$(utils::html_escape "${host}")" "${overall}" "${overall}"

  printf '<div class="grid">\n'

  printf '<section><h3>Rede</h3><table>\n'
  html::_kv "IPv4" dns.ipv4
  html::_kv "IPv6" dns.ipv6
  html::_kv "CDN" dns.cdn
  html::_kv "HTTP" http.status
  html::_kv "HTTPS" https.status
  printf '</table></section>\n'

  printf '<section><h3>TLS / Certificado</h3><table>\n'
  html::_kv "TLS" tls.negotiated
  html::_kv "Cipher" tls.cipher
  html::_kv "Certificado" cert.status
  html::_kv "Emissor" cert.issuer_org
  html::_kv "Chave" cert.key_type
  html::_kv "Dias restantes" cert.days_left
  printf '</table></section>\n'

  printf '<section><h3>Servidor</h3><table>\n'
  html::_kv "Software" server.software
  html::_kv "Versao" server.version
  html::_kv "Sistema" server.os
  html::_kv "Ultima versao" version.latest
  html::_kv "Status" version.status
  html::_kv "HTTP/2" http.http2
  html::_kv "HTTP/3" http.http3
  printf '</table></section>\n'

  printf '<section><h3>Seguranca</h3><table>\n'
  html::_kv "HSTS" sec.hsts
  html::_kv "CSP" sec.csp
  html::_kv "Referrer-Policy" sec.referrer
  html::_kv "Pontuacao" sec.score
  html::_kv "CVEs" cve.status
  printf '</table></section>\n'

  printf '</div>\n'  # grid

  # Tabela de CVEs, se houver.
  if utils::result_has cve.list; then
    printf '<section><h3>Vulnerabilidades</h3><table class="cve">\n'
    printf '<tr><td class="k">ID</td><td class="k">Detalhe</td></tr>\n'
    local l id rest
    while IFS= read -r l; do
      [[ -z "${l}" ]] && continue
      id="$(printf '%s' "${l}" | cut -f1)"
      rest="$(utils::html_escape "$(printf '%s' "${l}" | cut -f2- | tr '\t' ' | ')")"
      printf '<tr><td class="v">%s</td><td class="v">%s</td></tr>\n' \
        "$(utils::html_escape "${id}")" "${rest}"
    done <<<"$(utils::result_get cve.list)"
    printf '</table></section>\n'
  fi

  printf '<section><table><tr><td class="k">Tempo</td><td class="v">%s s</td></tr></table></section>\n' "${elapsed}"
  printf '</div>\n'  # card
}
