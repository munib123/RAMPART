# Vulnerability: CakePHP - Debug Kit Toolbar Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`cakephp-debugkit-exposure.yaml`)

## Description
Detected CakePHP Debug Kit toolbar, potentially leaking sensitive application information, database queries, and configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/debug-kit
```

