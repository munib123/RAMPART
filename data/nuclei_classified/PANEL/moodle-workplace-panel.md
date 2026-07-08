# Vulnerability: Moodle Workplace Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`moodle-workplace-panel.yaml`)

## Description
Moodle workplace login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/index.php
```

