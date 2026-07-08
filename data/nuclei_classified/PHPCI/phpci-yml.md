# Vulnerability: PHPCI Configuration Exposure "phpci.yml" Exposure
**Classification:** PHPCI
**Source:** Nuclei Template (`phpci-yml.yaml`)

## Description
PHPCI Configuration "phpci.yml" File was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phpci.yml
GET {{BaseURL}}/ci/phpci.yml
```

