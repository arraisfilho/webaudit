# Política de Segurança

## Escopo e uso responsável

O WebAudit é uma ferramenta de auditoria que realiza apenas coletas passivas
e consultas de leitura (resolução DNS, conexões TCP, requisições HTTP/HTTPS,
handshakes TLS e consultas a APIs públicas de CVE). Ela **não** executa testes
intrusivos, exploração de falhas ou qualquer ação que modifique o alvo.

Ainda assim, audite somente sistemas que você possui ou para os quais tem
autorização explícita. O uso indevido é de responsabilidade do usuário.

## Versões suportadas

| Versão | Suporte de segurança |
|--------|----------------------|
| 1.0.x  | Sim                  |

## Reportando uma vulnerabilidade

Se encontrar uma vulnerabilidade no próprio WebAudit (por exemplo, injeção de
comando via entrada não sanitizada, exposição de segredos em log/cache):

1. **Não** abra uma issue pública.
2. Envie os detalhes de forma privada para o mantenedor do repositório
   (endereço de contato indicado no perfil do projeto) ou use o canal privado
   de _security advisories_ do GitHub.
3. Inclua passos de reprodução, impacto potencial e, se possível, uma sugestão
   de correção.

Você receberá uma confirmação de recebimento e será mantido informado sobre a
correção e a divulgação coordenada.

## Boas práticas ao usar a ferramenta

- Trate chaves de API (NVD, GitHub) como segredos: prefira variáveis de
  ambiente ou um `config.local.conf` fora do controle de versão.
- O diretório de cache pode conter respostas de APIs; restrinja permissões se
  o host for compartilhado.
- Arquivos de log podem registrar hosts auditados; proteja-os conforme sua
  política interna.
