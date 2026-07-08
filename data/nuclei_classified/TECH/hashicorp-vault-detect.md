# Vulnerability: HashiCorp Vault Detect
**Classification:** TECH
**Source:** Nuclei Template (`hashicorp-vault-detect.yaml`)

## Description
Detects HashiCorp Vault

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v1/sys/seal-status
GET {{BaseURL}}/ui/vault/auth
```

