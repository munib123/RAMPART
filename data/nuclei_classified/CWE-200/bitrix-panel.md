# Vulnerability: Bitrix Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`bitrix-panel.yaml`)

## Description
Bitrix24 is a unified work space that places a complete set of business tools into a single, intuitive interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bitrix/admin/
GET {{BaseURL}}/bitrix/components/bitrix/map.yandex.view/settings/settings.php
```

