# Vulnerability: Aerohive NetConfig UI
**Classification:** CWE-200
**Source:** Nuclei Template (`aerohive-netconfig-ui.yaml`)

## Description
An Aerohive NetConfig user interface was detected. The NetConfig UI provides a fundamental set of configurations for configuring basic network and HiveManager connectivity settings, and uploading new IQ Engine images to Extreme Networks APs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php5
```

