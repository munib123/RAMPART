# Vulnerability: Vault Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vault-panel.yaml`)

## Description
Vault login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v1/sys/health
GET {{BaseURL}}/ui/vault/auth
GET {{BaseURL}}/ui/auth
GET {{BaseURL}}/v1/sys/health?help=1
```

