# Vulnerability: Fcv User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fcv.yaml`)

## Description
Fcv user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://fcv.if.ua/index.php/component/comprofiler/userprofile/{{user}}/
```

