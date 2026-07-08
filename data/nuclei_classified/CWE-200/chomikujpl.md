# Vulnerability: Chomikuj.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`chomikujpl.yaml`)

## Description
Chomikuj.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://chomikuj.pl/{{user}}/
```

