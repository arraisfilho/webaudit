#!/usr/bin/env bash
#
# json.sh - Saída em JSON.
#
# Responsabilidade única: serializar o result store de um host em um objeto
# JSON válido. Usa jq quando disponível para garantir escaping correto;
# caso contrário, monta o JSON manualmente com utils::json_escape.
#
# O scanner agrega múltiplos objetos em um array (ver webaudit.sh).
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_JSON_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_JSON_LOADED=1

# json::emit <host> <elapsed> - imprime um objeto JSON do host.
json::emit() {
  local host="$1" elapsed="$2"

  if utils::has jq; then
    json::_emit_jq "${host}" "${elapsed}"
  else
    json::_emit_manual "${host}" "${elapsed}"
  fi
}

# json::_emit_jq - constrói o JSON via jq a partir de pares chave=valor.
json::_emit_jq() {
  local host="$1" elapsed="$2" k
  {
    printf '%s\n' "host	${host}"
    printf '%s\n' "elapsed_seconds	${elapsed}"
    printf '%s\n' "overall	$(report::overall)"
    for k in "${WEBAUDIT_RESULT_ORDER[@]}"; do
      printf '%s\t%s\n' "${k}" "${WEBAUDIT_RESULT[$k]}"
    done
  } | jq -R -s '
    split("\n") | map(select(length>0)) |
    map(. / "\t") | map({key: .[0], value: (.[1:] | join("\t"))}) |
    from_entries
  '
}

# json::_emit_manual - fallback sem jq.
json::_emit_manual() {
  local host="$1" elapsed="$2" k v first=1
  printf '{\n'
  printf '  "host": "%s",\n' "$(utils::json_escape "${host}")"
  printf '  "elapsed_seconds": "%s",\n' "$(utils::json_escape "${elapsed}")"
  printf '  "overall": "%s",\n' "$(report::overall)"
  printf '  "results": {\n'
  for k in "${WEBAUDIT_RESULT_ORDER[@]}"; do
    v="$(utils::json_escape "${WEBAUDIT_RESULT[$k]}")"
    [[ ${first} -eq 1 ]] && first=0 || printf ',\n'
    printf '    "%s": "%s"' "${k}" "${v}"
  done
  printf '\n  }\n}\n'
}
