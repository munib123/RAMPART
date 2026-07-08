# Vulnerability: KnowYourMeme User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`knowyourmeme.yaml`)

## Description
KnowYourMeme user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://knowyourmeme.com/users/{{user}}
```

