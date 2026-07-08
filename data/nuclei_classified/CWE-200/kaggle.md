# Vulnerability: Kaggle User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kaggle.yaml`)

## Description
Kaggle user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.kaggle.com/{{user}}
```

