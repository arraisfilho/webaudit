# Makefile - WebAudit
#
# Alvos principais:
#   make            -> valida sintaxe de todos os scripts
#   make install    -> instala em PREFIX (padrão /usr/local)
#   make uninstall  -> remove a instalação
#   make test       -> roda os testes automatizados (tests/)
#   make lint       -> roda ShellCheck em todos os scripts
#   make clean      -> limpa cache e artefatos temporários
#   make release    -> gera o tarball de distribuição

SHELL       := /bin/bash
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
LIBDIR      := $(PREFIX)/lib/webaudit
VERSION     := $(shell sed -n 's/^WEBAUDIT_VERSION="\(.*\)"/\1/p' lib/cli.sh | head -n1)

MAIN        := webaudit.sh
LIBS        := $(wildcard lib/*.sh)
TESTS       := $(wildcard tests/*.sh)
DIST        := webaudit-$(VERSION).tar.gz

.PHONY: all check install uninstall test lint clean release help

all: check

## check: valida a sintaxe (bash -n) de todos os scripts
check:
	@echo ">> Verificando sintaxe..."
	@bash -n $(MAIN)
	@for f in $(LIBS) $(TESTS); do bash -n "$$f" || exit 1; done
	@echo "OK: sintaxe valida em todos os scripts."

## install: instala o webaudit em $(PREFIX)
install:
	@echo ">> Instalando em $(PREFIX)..."
	@install -d "$(LIBDIR)/lib"
	@install -m 0755 $(MAIN) "$(LIBDIR)/$(MAIN)"
	@install -m 0644 $(LIBS) "$(LIBDIR)/lib/"
	@[ -f config.conf ] && install -m 0644 config.conf "$(LIBDIR)/config.conf" || true
	@install -d "$(BINDIR)"
	@ln -sf "$(LIBDIR)/$(MAIN)" "$(BINDIR)/webaudit"
	@echo "OK: instalado. Execute 'webaudit --help'."

## uninstall: remove a instalação
uninstall:
	@echo ">> Removendo instalacao..."
	@rm -f "$(BINDIR)/webaudit"
	@rm -rf "$(LIBDIR)"
	@echo "OK: removido."

## test: executa a suíte de testes
test: check
	@echo ">> Executando testes..."
	@bash tests/run_tests.sh

## lint: roda ShellCheck (se instalado)
lint:
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck nao encontrado"; exit 1; }
	@echo ">> Rodando shellcheck..."
	@shellcheck -x $(MAIN) $(LIBS)
	@echo "OK: shellcheck sem erros."

## clean: limpa cache e temporários
clean:
	@echo ">> Limpando cache..."
	@rm -rf cache/* 2>/dev/null || true
	@rm -f $(DIST) 2>/dev/null || true
	@echo "OK."

## release: gera o tarball de distribuição
release: check
	@echo ">> Gerando $(DIST)..."
	@tar --exclude='cache/*' --exclude='.git' -czf "$(DIST)" \
		$(MAIN) lib docs tests Makefile README.md CHANGELOG.md \
		CONTRIBUTING.md SECURITY.md CODE_OF_CONDUCT.md LICENSE \
		.github .gitignore .shellcheckrc config.conf
	@echo "OK: $(DIST) gerado."

## help: lista os alvos
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
