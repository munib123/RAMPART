# Vulnerability: Wikipedia User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wikipedia.yaml`)

## Description
Wikipedia user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://en.wikipedia.org/w/api.php?action=query&format=json&list=users&ususers={{user}}
```

