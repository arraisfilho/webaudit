#!/usr/bin/env bash
#
# deps.sh - Checagem de dependencias de runtime do WebAudit.
#
# Responsabilidade única: validar dependências obrigatórias antes da auditoria
# e avisar sobre dependências opcionais que reduzem funcionalidades.
#
# shellcheck shell=bash

if [[ -n "${__WEBAUDIT_DEPS_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
__WEBAUDIT_DEPS_LOADED=1

# deps::check_runtime - valida dependências e imprime instruções de instalação.
deps::check_runtime() {
  local -a missing_required=()
  local -a missing_optional=()

  deps::_check_bash_version || missing_required+=("bash >= 3.2")

  local cmd
  for cmd in curl openssl; do
    utils::has "${cmd}" || missing_required+=("${cmd}")
  done

  if ! utils::has jq; then
    if [[ "${WEBAUDIT_CVE_ENABLED:-1}" == "1" ]]; then
      missing_optional+=("jq (CVEs e JSON mais robustos)")
    else
      missing_optional+=("jq (JSON mais robusto)")
    fi
  fi

  if ! utils::has dig && ! utils::has host && ! utils::has getent; then
    missing_optional+=("dig ou host (consultas DNS completas)")
  fi

  if ! utils::has timeout && ! utils::has gtimeout; then
    missing_optional+=("timeout/gtimeout (limite de tempo externo)")
  fi

  utils::has nc || missing_optional+=("nc/netcat (fallback de teste TCP)")

  if (( ${#missing_required[@]} > 0 )); then
    utils::error "Dependencias obrigatorias ausentes: $(deps::_join ', ' "${missing_required[@]}")"
    deps::_print_install_hints
    return 3
  fi

  if (( ${#missing_optional[@]} > 0 )); then
    utils::warn "Dependencias opcionais ausentes: $(deps::_join ', ' "${missing_optional[@]}")"
    utils::warn "A auditoria continua, mas algumas verificacoes podem ficar limitadas."
    deps::_print_install_hints
  fi

  return 0
}

deps::_check_bash_version() {
  [[ -n "${BASH_VERSION:-}" ]] || return 1
  (( BASH_VERSINFO[0] > 3 )) && return 0
  (( BASH_VERSINFO[0] == 3 && BASH_VERSINFO[1] >= 2 )) && return 0
  return 1
}

deps::_join() {
  local sep="$1"; shift
  local out="" item
  for item in "$@"; do
    out="${out}${out:+${sep}}${item}"
  done
  printf '%s' "${out}"
}

deps::_print_install_hints() {
  case "${WEBAUDIT_OS:-unknown}" in
    macos)
      cat >&2 <<'EOF'

Instalacao sugerida no macOS (Homebrew):
  brew install bash curl openssl jq bind coreutils

Observacao: o macOS normalmente ja inclui nc/netcat. Se necessario, instale via:
  brew install netcat
EOF
      ;;
    linux)
      cat >&2 <<'EOF'

Instalacao sugerida no Linux:
  Debian/Ubuntu:
    sudo apt-get update && sudo apt-get install -y bash curl openssl jq dnsutils netcat-openbsd coreutils

  Fedora/RHEL:
    sudo dnf install -y bash curl openssl jq bind-utils nmap-ncat coreutils

  Alpine:
    sudo apk add bash curl openssl jq bind-tools netcat-openbsd coreutils
EOF
      ;;
    bsd)
      cat >&2 <<'EOF'

Instalacao sugerida em BSD:
  pkg install bash curl openssl jq bind-tools coreutils
EOF
      ;;
    *)
      cat >&2 <<'EOF'

Instale ao menos as dependencias obrigatorias:
  bash curl openssl

Dependencias opcionais recomendadas:
  jq dig/host timeout/gtimeout nc/netcat
EOF
      ;;
  esac
}
