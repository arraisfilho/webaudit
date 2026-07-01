#!/usr/bin/env bash
#
# security.sh - Avaliação dos cabeçalhos de segurança HTTP.
#
# Responsabilidade única: verificar a presença e o estado dos principais
# cabeçalhos de segurança a partir de WEBAUDIT_RAW_HEADERS e produzir uma nota
# geral (OK/WARNING/CRITICAL) e uma pontuação.
#
# Cabeçalhos avaliados: HSTS (Strict-Transport-Security), Content-Security-Policy,
# Referrer-Policy, Permissions-Policy, X-Frame-Options, X-Content-Type-Options,
# Cross-Origin-{Embedder,Opener,Resource}-Policy, Expect-CT.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_SECURITY_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_SECURITY_LOADED=1

# security::_present <cabecalho> <chave_resultado>
# Marca "OK" se presente (armazena o valor), "Ausente" caso contrário.
security::_present() {
  local hdr="$1" key="$2" val
  val="$(http::header_value "${hdr}")"
  if [[ -n "${val}" ]]; then
    utils::result_set "${key}" "${val}"
    return 0
  fi
  utils::result_set "${key}" "Ausente"
  return 1
}

# security::run <host> - avalia os cabeçalhos e calcula a pontuação.
security::run() {
  local host="$1"
  utils::debug "SECURITY: avaliando cabeçalhos de segurança de ${host}"

  local score=0 max=0

  # Pesos: críticos valem 2, os demais 1.
  security::_present 'strict-transport-security' sec.hsts       && score=$((score+2)); max=$((max+2))
  security::_present 'content-security-policy'    sec.csp        && score=$((score+2)); max=$((max+2))
  security::_present 'x-content-type-options'     sec.xcto       && score=$((score+1)); max=$((max+1))
  security::_present 'x-frame-options'            sec.xfo        && score=$((score+1)); max=$((max+1))
  security::_present 'referrer-policy'            sec.referrer   && score=$((score+1)); max=$((max+1))
  security::_present 'permissions-policy'         sec.permissions&& score=$((score+1)); max=$((max+1))
  security::_present 'cross-origin-embedder-policy' sec.coep     && score=$((score+1)); max=$((max+1))
  security::_present 'cross-origin-opener-policy'   sec.coop     && score=$((score+1)); max=$((max+1))
  security::_present 'cross-origin-resource-policy' sec.corp     && score=$((score+1)); max=$((max+1))
  security::_present 'expect-ct'                  sec.expect_ct  && score=$((score+0)); max=$((max+0)) || true

  utils::result_set sec.score "${score}/${max}"

  # Análise específica de HSTS (max-age suficiente e includeSubDomains).
  local hsts; hsts="$(utils::result_get sec.hsts)"
  if [[ "${hsts}" != "Ausente" ]]; then
    local maxage
    maxage="$(printf '%s' "${hsts}" | grep -oE 'max-age=[0-9]+' | grep -oE '[0-9]+' || echo 0)"
    if (( maxage < 15552000 )); then
      utils::result_set sec.hsts_note "max-age baixo (<180d)"
    fi
  fi

  # Nota geral.
  local pct=0
  if (( max > 0 )); then pct=$(( score * 100 / max )); fi
  if [[ "$(utils::result_get sec.hsts)" == "Ausente" || "$(utils::result_get sec.csp)" == "Ausente" ]]; then
    utils::result_set sec.rating "WARNING"
  elif (( pct >= 70 )); then
    utils::result_set sec.rating "OK"
  else
    utils::result_set sec.rating "WARNING"
  fi
}
