# Vulnerability: Bitrix Site Manager - Log File Disclosure
**Classification:** CWE-532
**Source:** Nuclei Template (`bitrix-log-file-disclosure.yaml`)

## Description
Detected Bitrix Site Manager log files, potentially exposing sensitive information including database credentials, file paths, SQL queries, and user session data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bitrix/modules/updater.log
GET {{BaseURL}}/bitrix/modules/updater_partner.log
```

