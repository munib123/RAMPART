# Vulnerability: Igromania User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`igromania.yaml`)

## Description
Igromania user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://forum.igromania.ru/member.php?username={{user}}
```

