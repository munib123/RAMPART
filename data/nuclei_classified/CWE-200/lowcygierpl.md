# Vulnerability: Lowcygier.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`lowcygierpl.yaml`)

## Description
Lowcygier.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bazar.lowcygier.pl/user/{{user}}
```

