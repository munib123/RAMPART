# Vulnerability: PHP Prober - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`php-prober-exposure.yaml`)

## Description
PHP Prober Server exposure was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/prober.php
```

