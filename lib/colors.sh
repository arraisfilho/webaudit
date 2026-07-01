#!/usr/bin/env bash
#
# colors.sh - Definições de cores ANSI para o WebAudit.
#
# Responsabilidade única: expor variáveis de cor e helpers de colorização.
# As cores são desativadas automaticamente quando a saída não é um terminal
# (pipe/arquivo) ou quando a variável NO_COLOR está definida.
#
# Uso:
#   source lib/colors.sh
#   printf '%b\n' "${C_GREEN}OK${C_RESET}"
#
# shellcheck shell=bash

# Evita redefinição em múltiplos sources.
if [[ -n "${__WEBAUDIT_COLORS_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_COLORS_LOADED=1

# colors::enabled - decide se cores devem ser usadas.
# Retorno: 0 (sim) / 1 (não)
colors::enabled() {
  [[ -n "${NO_COLOR:-}" ]] && return 1
  [[ "${WEBAUDIT_NO_COLOR:-0}" == "1" ]] && return 1
  [[ -t 1 ]] || return 1
  return 0
}

# colors::init - inicializa (ou zera) todas as variáveis de cor.
colors::init() {
  if colors::enabled; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_MAGENTA=$'\033[35m'
    C_CYAN=$'\033[36m'
    C_GRAY=$'\033[90m'
  else
    C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW=''
    C_BLUE='' C_MAGENTA='' C_CYAN='' C_GRAY=''
  fi
  export C_RESET C_BOLD C_DIM C_RED C_GREEN C_YELLOW C_BLUE C_MAGENTA C_CYAN C_GRAY
}

# colors::paint <cor> <texto> - retorna texto colorido.
colors::paint() {
  local color="$1"; shift
  printf '%b%s%b' "${color}" "$*" "${C_RESET}"
}

colors::init
