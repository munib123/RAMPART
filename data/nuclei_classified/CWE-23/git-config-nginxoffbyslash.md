# Vulnerability: Nginx - Git Configuration Exposure
**Classification:** CWE-23
**Source:** Nuclei Template (`git-config-nginxoffbyslash.yaml`)

## Description
Nginx is vulnerable to git configuration exposure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

