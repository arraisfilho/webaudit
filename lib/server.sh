#!/usr/bin/env bash
#
# server.sh - Detecção do web server e do sistema operacional.
#
# Responsabilidade única: identificar o software servidor (nginx, Apache,
# LiteSpeed, OpenResty, Caddy, IIS, Traefik, HAProxy, Envoy, Tomcat, Jetty,
# Gunicorn, uWSGI) e inferir o sistema operacional/distribuição a partir dos
# cabeçalhos Server / X-Powered-By, quando não mascarados.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_SERVER_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_SERVER_LOADED=1

# server::detect_software <server_header> <powered_by> - retorna nome canônico.
server::detect_software() {
  local blob; blob="$(printf '%s %s' "$1" "${2:-}" | utils::lower)"
  case "${blob}" in
    *openresty*)  printf 'OpenResty' ;;
    *nginx*)      printf 'nginx' ;;
    *litespeed*)  printf 'LiteSpeed' ;;
    *apache*)     printf 'Apache' ;;
    *caddy*)      printf 'Caddy' ;;
    *microsoft-iis*|*iis*) printf 'IIS' ;;
    *traefik*)    printf 'Traefik' ;;
    *haproxy*)    printf 'HAProxy' ;;
    *envoy*)      printf 'Envoy' ;;
    *tomcat*|*coyote*) printf 'Tomcat' ;;
    *jetty*)      printf 'Jetty' ;;
    *gunicorn*)   printf 'Gunicorn' ;;
    *uwsgi*)      printf 'uWSGI' ;;
    *)            printf '' ;;
  esac
}

# server::detect_os <server_header> - infere SO/distribuição.
server::detect_os() {
  local blob; blob="$(printf '%s' "$1" | utils::lower)"
  case "${blob}" in
    *ubuntu*)       printf 'Ubuntu' ;;
    *debian*)       printf 'Debian' ;;
    *centos*)       printf 'CentOS' ;;
    *rocky*)        printf 'Rocky Linux' ;;
    *almalinux*|*alma*) printf 'AlmaLinux' ;;
    *fedora*)       printf 'Fedora' ;;
    *red?hat*|*rhel*) printf 'Red Hat' ;;
    *freebsd*)      printf 'FreeBSD' ;;
    *openbsd*)      printf 'OpenBSD' ;;
    *win32*|*win64*|*microsoft*) printf 'Windows Server' ;;
    *unix*)         printf 'Unix' ;;
    *)              printf '' ;;
  esac
}

# server::run <host> - popula server.* a partir dos cabeçalhos coletados.
server::run() {
  local host="$1"
  utils::debug "SERVER: identificando servidor de ${host}"

  local srv pby
  srv="$(utils::result_get header.server)"
  pby="$(utils::result_get header.x_powered_by)"

  utils::result_set server.banner "${srv:-oculto}"

  local sw; sw="$(server::detect_software "${srv}" "${pby}")"
  utils::result_set server.software "${sw:-desconhecido}"

  # Extração de versão do banner (ex.: nginx/1.28.3).
  local ver
  ver="$(printf '%s' "${srv}" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"
  utils::result_set server.version "${ver:-desconhecida}"

  # Sistema operacional (entre parênteses no banner do Apache, por ex.).
  local os
  os="$(server::detect_os "${srv}")"
  utils::result_set server.os "${os:-desconhecido}"

  # Banner mascarado?
  if [[ -z "${srv}" || "${sw}" == "" ]]; then
    utils::result_set server.masked "Sim"
  else
    utils::result_set server.masked "Nao"
  fi
}
