# Vulnerability: GoCd Encryption Key
**Classification:** GO
**Source:** Nuclei Template (`gocd-encryption-key.yaml`)

## Description
GoCd Encryption Key is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/go/add-on/business-continuity/api/cipher.aes
```

