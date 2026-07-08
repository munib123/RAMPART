# Vulnerability: Themeforest User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`themeforest.yaml`)

## Description
Themeforest user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://themeforest.net/user/{{user}}
```

