# Vulnerability: SugarCRM Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sugarcrm-panel.yaml`)

## Description
SugarCRM login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/index.php?action=Login&module=Users
```

