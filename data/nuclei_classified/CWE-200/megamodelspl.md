# Vulnerability: Megamodels.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`megamodelspl.yaml`)

## Description
Megamodels.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://megamodels.pl/{{user}}
```

