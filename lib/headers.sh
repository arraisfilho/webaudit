#!/usr/bin/env bash
#
# headers.sh - Extração de cabeçalhos HTTP informativos.
#
# Responsabilidade única: expor os cabeçalhos "de resposta" comuns a partir de
# WEBAUDIT_RAW_HEADERS (coletado pelo módulo http). Não faz novas requisições.
#
# Cabeçalhos: Server, Date, Via, ETag, Last-Modified, Cache-Control, Expires,
# Age, Connection, X-Powered-By.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_HEADERS_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_HEADERS_LOADED=1

# headers::run <host> - popula os campos header.*.
headers::run() {
  local host="$1"
  utils::debug "HEADERS: extraindo cabeçalhos de ${host}"

  utils::result_set header.server        "$(http::header_value 'server')"
  utils::result_set header.date          "$(http::header_value 'date')"
  utils::result_set header.via           "$(http::header_value 'via')"
  utils::result_set header.etag          "$(http::header_value 'etag')"
  utils::result_set header.last_modified "$(http::header_value 'last-modified')"
  utils::result_set header.cache_control "$(http::header_value 'cache-control')"
  utils::result_set header.expires       "$(http::header_value 'expires')"
  utils::result_set header.age           "$(http::header_value 'age')"
  utils::result_set header.connection    "$(http::header_value 'connection')"
  utils::result_set header.x_powered_by  "$(http::header_value 'x-powered-by')"
}
