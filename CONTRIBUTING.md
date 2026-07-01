# Contribuindo com o WebAudit

Obrigado pelo interesse em contribuir. Este documento resume o fluxo de
trabalho e os padrões do projeto.

## Ambiente

O WebAudit é escrito em Bash puro. Para desenvolver você precisa de:

- `bash` 4.0 ou superior (recomendado 5.x)
- `curl` e `openssl` (dependências de execução)
- [`shellcheck`](https://www.shellcheck.net) (análise estática)
- Opcional: `jq`, `dig`, `column` para funcionalidades estendidas

## Fluxo de trabalho

1. Faça um fork e crie um branch descritivo a partir de `main`:
   `git checkout -b feat/minha-melhoria`
2. Faça as alterações mantendo o estilo do código existente.
3. Rode a verificação estática e os testes antes de abrir o PR:
   ```sh
   make lint      # shellcheck -x
   make test      # testes unitários
   WEBAUDIT_TEST_NET=1 make test   # inclui testes de rede
   ```
4. Atualize o `CHANGELOG.md` na seção "Não lançado".
5. Abra o Pull Request explicando a motivação e o comportamento esperado.

## Padrões de código

- O projeto usa `set -Eeuo pipefail` e um `trap ERR`. Todo comando que pode
  falhar legitimamente deve ser guardado (`|| true`, `|| var=$?`, `if`).
- Funções seguem o prefixo de namespace por módulo, ex.: `tls::run`,
  `utils::trim`. Funções internas usam `_` após o namespace: `tls::_connect`.
- Evite bashismos incompatíveis quando houver alternativa portável; o alvo é
  Linux e macOS. Use os wrappers de `utils.sh` (`utils::epoch`,
  `utils::run_timeout`, `utils::has`) em vez de comandos específicos de SO.
- Prefira `printf` a `echo` para saída controlada.
- Escapes de saída (JSON/CSV/HTML) devem passar pelas funções de `utils.sh`.
- O código deve passar em `shellcheck -x` sem novos avisos. Supressões
  pontuais exigem comentário justificando.

## Escrevendo testes

Os testes ficam em `tests/run_tests.sh`. Testes de funções puras não devem
depender de rede. Testes que exigem rede ficam sob o bloco condicionado a
`WEBAUDIT_TEST_NET=1`.

## Reportando bugs e sugestões

Abra uma issue descrevendo o comando executado, a saída obtida, a saída
esperada e o ambiente (SO, versões de `bash`, `curl`, `openssl`).

## Segurança

Vulnerabilidades não devem ser reportadas via issue pública. Consulte
[`SECURITY.md`](SECURITY.md).
