# Vulnerability: WebCalendar Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`webcalendar-install.yaml`)

## Description
WebCalendar is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

