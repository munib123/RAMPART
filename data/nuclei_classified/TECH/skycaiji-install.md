# Vulnerability: SkyCaiji - Exposed Installation
**Classification:** TECH
**Source:** Nuclei Template (`skycaiji-install.yaml`)

## Description
SkyCaiji was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?s=/install/index/index
```

