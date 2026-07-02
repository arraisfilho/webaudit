#!/usr/bin/env bash
#
# versions.sh - Comparação da versão detectada com a última disponível.
#
# Responsabilidade única: dado o software e a versão extraídos pelo módulo
# server, consultar a última versão estável publicada e classificar o estado
# (atualizado / atualização recomendada / desconhecido).
#
# Fonte: API pública do endoflife.date (https://endoflife.date/docs/api),
# que expõe os ciclos de vida e a última versão de cada produto em JSON.
# Resultados são cacheados localmente (namespace "versions", TTL 24h).
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_VERSIONS_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_VERSIONS_LOADED=1

WEBAUDIT_EOL_API="https://endoflife.date/api"

# versions::_product <software> - mapeia o nome canônico para o slug do EOL.
versions::_product() {
  case "$(printf '%s' "$1" | utils::lower)" in
    nginx)      printf 'nginx' ;;
    openresty)  printf 'nginx' ;;
    apache)     printf 'apache-http-server' ;;
    tomcat)     printf 'tomcat' ;;
    haproxy)    printf 'haproxy' ;;
    *)          printf '' ;;
  esac
}

# versions::_fetch_latest <slug> <major.minor?> - retorna latest do EOL.
# Consulta o ciclo mais recente; se houver versão detectada, tenta casar o
# ciclo correspondente (ex.: 1.28) para uma comparação justa.
versions::_fetch_latest() {
  local slug="$1" detected="$2"
  local body
  if ! body="$(utils::cache_get versions "eol:${slug}")"; then
    http::_curl_base
    local -a opts=("${WEBAUDIT_CURL_OPTS[@]}")
    body="$(curl "${opts[@]}" "${WEBAUDIT_EOL_API}/${slug}.json" 2>/dev/null || true)"
    [[ -n "${body}" ]] && utils::cache_set versions "eol:${slug}" 86400 "${body}"
  fi
  [[ -n "${body}" ]] || { printf ''; return 1; }

  # Preferir jq quando disponível.
  local cycle_major="" latest=""
  cycle_major="$(printf '%s' "${detected}" | grep -oE '^[0-9]+\.[0-9]+' | head -n1)"

  if utils::has jq; then
    if [[ -n "${cycle_major}" ]]; then
      latest="$(printf '%s' "${body}" | jq -r --arg c "${cycle_major}" \
        '.[] | select(.cycle==$c) | .latest' 2>/dev/null | head -n1)"
    fi
    [[ -z "${latest}" || "${latest}" == "null" ]] && \
      latest="$(printf '%s' "${body}" | jq -r '.[0].latest' 2>/dev/null)"
  else
    # Fallback sem jq: extrai o primeiro "latest".
    latest="$(printf '%s' "${body}" \
      | grep -oE '"latest":"[^"]+"' | head -n1 | sed 's/.*:"//;s/"//')"
  fi
  [[ "${latest}" == "null" ]] && latest=""
  printf '%s' "${latest}"
}

# versions::_cmp <a> <b> - compara versões. Ecoa: lt (a<b), eq (a==b), gt (a>b).
# Evita retornar "-1" (que alguns printf/shells tratam como opção).
versions::_cmp() {
  local a="$1" b="$2"
  [[ "${a}" == "${b}" ]] && { printf '%s' 'eq'; return; }
  local hi
  hi="$(printf '%s\n%s\n' "${a}" "${b}" | sort -V | tail -n1)"
  if [[ "${hi}" == "${a}" ]]; then printf '%s' 'gt'; else printf '%s' 'lt'; fi
}

# versions::run <host> - executa a comparação.
versions::run() {
  # host recebido por assinatura; a coleta usa server.software/version.
  local sw ver
  sw="$(utils::result_get server.software)"
  ver="$(utils::result_get server.version)"

  if [[ -z "${ver}" || "${ver}" == "desconhecida" ]]; then
    utils::result_set version.latest "desconhecida"
    utils::result_set version.status "Versao mascarada - nao foi possivel comparar"
    return 0
  fi

  local slug; slug="$(versions::_product "${sw}")"
  if [[ -z "${slug}" ]]; then
    utils::result_set version.latest "nao suportado"
    utils::result_set version.status "Produto sem base de versoes conhecida"
    return 0
  fi

  utils::debug "VERSIONS: consultando ultima versao de ${slug}"
  local latest; latest="$(versions::_fetch_latest "${slug}" "${ver}")"
  if [[ -z "${latest}" ]]; then
    utils::result_set version.latest "indisponivel"
    utils::result_set version.status "Nao foi possivel obter a ultima versao"
    return 0
  fi

  utils::result_set version.latest "${latest}"
  local cmp; cmp="$(versions::_cmp "${ver}" "${latest}")"
  case "${cmp}" in
    eq) utils::result_set version.status "Atualizado" ;;
    gt) utils::result_set version.status "Versao mais recente que a base (pre-release?)" ;;
    lt) utils::result_set version.status "Atualizacao recomendada" ;;
    *)  utils::result_set version.status "Comparacao indisponivel" ;;
  esac
}
