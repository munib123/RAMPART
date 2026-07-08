# Vulnerability: IMGSRC.RU User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`imgsrcru.yaml`)

## Description
IMGSRC.RU user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://imgsrc.ru/main/user.php?lang=ru&user={{user}}
```

