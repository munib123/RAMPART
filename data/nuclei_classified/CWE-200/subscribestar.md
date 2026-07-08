# Vulnerability: Subscribestar User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`subscribestar.yaml`)

## Description
Subscribestar user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://subscribestar.adult/{{user}}
```

