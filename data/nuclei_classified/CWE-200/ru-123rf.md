# Vulnerability: Ru 123rf User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ru-123rf.yaml`)

## Description
Ru 123rf user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ru.123rf.com/profile_{{user}}
```

