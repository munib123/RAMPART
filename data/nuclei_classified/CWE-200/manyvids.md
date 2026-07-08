# Vulnerability: MANYVIDS User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`manyvids.yaml`)

## Description
MANYVIDS user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.manyvids.com/results.php?keywords={{user}}
```

