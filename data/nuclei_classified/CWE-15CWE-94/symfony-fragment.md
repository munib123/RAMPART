# Vulnerability: Symfony _fragment - Detect
**Classification:** CWE-15,CWE-94
**Source:** Nuclei Template (`symfony-fragment.yaml`)

## Description
Symfony servers support a "/_fragment" command that allows clients to provide custom PHP commands and return the HTML output.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_fragment
```

