# Vulnerability: Zentao Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zentao-detect.yaml`)

## Description
Zentao panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/zentao/index.php?mode=getconfig
```

