# Vulnerability: Ruijie Phpinfo Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ruijie-phpinfo.yaml`)

## Description
Ruijie phpinfo configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tool/view/phpinfo.view.php
```

