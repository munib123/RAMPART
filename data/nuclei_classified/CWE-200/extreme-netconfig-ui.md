# Vulnerability: Extreme NetConfig UI Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`extreme-netconfig-ui.yaml`)

## Description
Extreme NetConfig UI panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php5
```

