# Nuclei Template: Bitrix Site Manager - Log File Disclosure
**Template ID:** bitrix-log-file-disclosure
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**Severity:** Medium
**CWE:** CWE-532
**Source:** Nuclei Template (`bitrix-log-file-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Bitrix Site Manager log files, potentially exposing sensitive information including database credentials, file paths, SQL queries, and user session data.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/bitrix/modules/updater.log
GET {{BaseURL}}/bitrix/modules/updater_partner.log
```

## References
- https://dev.1c-bitrix.ru/learning/course/index.php?COURSE_ID=43&LESSON_ID=2795
- https://dev.1c-bitrix.ru/api_help/main/general/error.php
