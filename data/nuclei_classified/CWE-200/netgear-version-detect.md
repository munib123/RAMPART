# Vulnerability: NETGEAR Router Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netgear-version-detect.yaml`)

## Description
NETGEAR router panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/currentsetting.htm
```

