# Vulnerability: Mercurial Ignore - File Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`mercurial-hgignore.yaml`)

## Description
Mercurial Ignore file disclosure was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.hgignore
```

