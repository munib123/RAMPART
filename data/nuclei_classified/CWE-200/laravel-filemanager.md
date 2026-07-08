# Vulnerability: Laravel File Manager - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`laravel-filemanager.yaml`)

## Description
Laravel File Manager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/laravel-filemanager?type=Files
```

