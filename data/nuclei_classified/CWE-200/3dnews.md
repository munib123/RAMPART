# Vulnerability: 3DNews User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`3dnews.yaml`)

## Description
3DNews user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://forum.3dnews.ru/member.php?username={{user}}
```

