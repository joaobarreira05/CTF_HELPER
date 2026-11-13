# Information Leakage — Guia Completo

> Informação sensível exposta por descuido. Não precisas de exploitar código — só de **encontrar** onde está.

## CWEs
- CWE-200 — Exposure of Sensitive Information
- CWE-209 — Error Message Information Leak
- CWE-489 — Active Debug Code
- CWE-538 — File/Directory Accessible Externally
- CWE-615 — Information in Comments

---

## Como reconhecer um challenge de infoleak

- A descrição fala em "find", "discover", "hidden", "look closely"
- Não há form de login nem input óbvio para injetar
- A app parece simples demais — a vulnerabilidade está no que **não** se vê

---

## Metodologia de reconhecimento (ordem recomendada)

### 1. Headers HTTP
```bash
curl -v http://TARGET/ 2>&1 | grep -iE 'server:|x-powered|set-cookie|x-debug|x-request|via:'
```
- `Server: Apache/2.4.51` → versão exata (pode ter CVEs)
- `X-Powered-By: PHP/7.4` → tecnologia backend
- `X-Debug-Token` → debug mode ativo
- Cookies com nomes interessantes (session, JWT, role)

### 2. View source — comentários HTML
```bash
curl -s http://TARGET/ | grep -iE '<!--|flag|secret|password|token|TODO|FIXME|hidden|key|admin'
```
Devs deixam comentários com:
- Credenciais de teste: `<!-- admin/test123 -->`
- Flags diretas: `<!-- FLAG: flag{...} -->`
- TODOs com informação sensível: `<!-- TODO: remove debug endpoint -->`

### 3. robots.txt e sitemap.xml
```bash
curl -s http://TARGET/robots.txt
curl -s http://TARGET/sitemap.xml
```
`robots.txt` com `Disallow: /admin-secret/` é um **mapa** de coisas interessantes, não proteção.

### 4. Ficheiros de backup e artefactos de editores
```bash
# Testa variantes de ficheiros conhecidos
for base in config app settings database index; do
  for ext in .py .php .js .yml .json .cfg .ini .xml; do
    for bak in .bak .old .orig .save .swp "~" .copy .tmp .backup; do
      URL="http://TARGET/static/${base}${ext}${bak}"
      CODE=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
      [ "$CODE" != "404" ] && [ "$CODE" != "403" ] && echo "$URL → $CODE"
    done
  done
done
```

Artefactos comuns:
| Artefacto | Como aparece |
|-----------|-------------|
| vim swap | `.config.py.swp`, `.config.py.swo` |
| vim backup | `config.py~` |
| emacs | `config.py~`, `#config.py#` |
| cp manual | `config.py.bak`, `config.py.old`, `config.py.orig` |
| macOS | `.DS_Store` |

### 5. Endpoints de debug e admin
```bash
for ep in /debug /debug/env /debug/vars /status /health /admin \
          /metrics /info /trace /actuator /actuator/env \
          /server-status /server-info /_debug /console \
          /phpinfo.php /elmah.axd /error_log; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET$ep")
  [ "$CODE" != "404" ] && echo "$ep → $CODE"
done
```

`/debug/env` é o clássico do prof — expõe `os.environ` com a FLAG.

### 6. Directory listing
```bash
for dir in / /static/ /public/ /uploads/ /files/ /export/ /backup/ \
           /data/ /logs/ /tmp/ /assets/ /media/; do
  BODY=$(curl -s "http://TARGET${dir}")
  echo "$BODY" | grep -qi "index of\|directory listing\|parent directory\|<a href=" && \
    echo "LISTING: $dir"
done
```
Se listing está ativo, procura ficheiros com nomes sugestivos: `flag.txt`, `secret.key`, `dump.sql`, `credentials.json`.

### 7. .git exposto
```bash
curl -s http://TARGET/.git/HEAD
```
Se responde `ref: refs/heads/main` (ou similar) → repo exposto!

```bash
# Commit messages — muitas vezes têm segredos
curl -s http://TARGET/.git/logs/HEAD

# Config — pode ter URLs com tokens
curl -s http://TARGET/.git/config

# Se quiseres reconstruir o repo inteiro (com git-dumper na VM se disponível):
# Manualmente:
curl -s http://TARGET/.git/refs/heads/main          # hash do último commit
curl -s http://TARGET/.git/objects/<2chars>/<rest>   # objetos git
```

### 8. JavaScript client-side
```bash
# Listar scripts carregados
curl -s http://TARGET/ | grep -oP 'src="[^"]+"'

# Procurar constantes, API keys, IDs hardcoded
curl -s http://TARGET/static/app.js | grep -iE 'ADMIN|KEY|SECRET|FLAG|TOKEN|PASSWORD|API|ID\s*='

# Procurar endpoints escondidos
curl -s http://TARGET/static/app.js | grep -oP '"/[a-zA-Z0-9_/]+"'
```

### 9. Erros verbosos / stack traces
Provocar erros para ver se mostram informação:
```bash
curl -s http://TARGET/crash                    # endpoint de crash
curl -s http://TARGET/inexistente              # 404 com detalhes?
curl -s "http://TARGET/?id=abc"                # tipo errado
curl -s "http://TARGET/search?q=%00"           # null byte
curl -s "http://TARGET/search?q='"             # SQL error?
curl -s -X POST http://TARGET/login -d ""      # campos vazios
```
Stack traces com variáveis locais podem conter a flag diretamente.

### 10. JWT e cookies — descodificar SEMPRE
```bash
# JWT (3 partes separadas por .)
echo "PAYLOAD_PARTE2" | base64 -d 2>/dev/null

# Cookie genérico em base64
echo "COOKIE_VALUE" | base64 -d 2>/dev/null

# URL decode
echo "VALOR" | python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))"
```
**JWT não é encriptado.** Qualquer dado no payload é legível — pode conter a flag.

### 11. Parâmetros escondidos
```bash
# Testar parâmetros que expõem mais dados
for p in verbose debug full details raw internal admin; do
  curl -s "http://TARGET/api/users/1?${p}=true" | head -5
  echo "---"
done
```

### 12. IDOR + leak combinado
Se a app tem IDs sequenciais (`/api/users/1`), enumera:
```bash
for i in $(seq 1 20); do
  echo "=== $i ==="
  curl -s "http://TARGET/api/users/$i?verbose=true"
done
```

---

## Padrões dos challenges do professor

| Challenge | Técnica | Dica rápida |
|-----------|---------|-------------|
| leak1 | Backup file (.bak) | `config.py.bak` no `/static/` |
| leak2 | Debug endpoint | `/debug/env` expõe `os.environ` |
| leak3 | Directory listing | `/public/` com listing ativo |
| leak4 | .git exposto | `.git/logs/HEAD` tem flag no commit message |
| leak5 | IDOR + verbose param | `/api/users/7?verbose=true` |
| leak6 | JWT payload | Base64-decode do payload JWT |
| leak7 | Prefix oracle | `/oracle?prefix=flag{` → brute-force char a char |
| leak8 | robots.txt | `Disallow: /admin-secret/` |
| leak9 | HTML comment | `<!-- FLAG: ... -->` no source |
| leak10 | Stack trace | `/crash` mostra variáveis locais |

---

## Fix / mitigação

| Problema | Fix |
|----------|-----|
| Ficheiros backup | Limpar artefactos antes de deploy; .gitignore |
| Debug endpoints | Remover em produção; proteger com auth |
| Directory listing | Desativar no web server |
| .git exposto | Bloquear `/.git/` no web server |
| Comentários HTML | Não pôr segredos em comentários |
| JWT com dados sensíveis | JWT é signed, não encrypted — nunca meter segredos |
| Erros verbosos | Error handlers genéricos em produção |
| IDs sequenciais | Verificar ownership; não expor campos internos |
| robots.txt | Não confiar como controlo de acesso |
