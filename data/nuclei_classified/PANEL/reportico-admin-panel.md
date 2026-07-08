# Vulnerability: Reportico Administration Page - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`reportico-admin-panel.yaml`)

## Description
Create a simple report using the designer front end in seconds from a single SQL statement. Add expressions, user criteria, charts, groups, aggregations, page headers, page footers, hyperlinks and even custom plugin code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/run.php?project=admin&execute_mode=ADMIN&clear_session=1
GET {{BaseURL}}/reportico/run.php?project=admin&execute_mode=ADMIN&clear_session=1
```

