# Vulnerability: Calendarix Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`calendarix-panel.yaml`)

## Description
Calendarix admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/calendarix/admin/cal_login.php
GET {{BaseURL}}/calendar/admin/cal_login.php
```

