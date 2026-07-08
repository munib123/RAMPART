# Vulnerability: Cowboys4angels User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cowboys4angels.yaml`)

## Description
Cowboys4angels user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cowboys4angels.com/cowboy/{{user}}/
```

