# Vulnerability: Woodwing Studio Server - Phpinfo Config
**Classification:** MISCONFIG
**Source:** Nuclei Template (`woodwing-phpinfo.yaml`)

## Description
Phpinfo Config file exposed in Woodwing Studio Server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/StudioServer/server/wwtest/phpinfo.php
GET {{BaseURL}}/server/wwtest/phpinfo.php
```

