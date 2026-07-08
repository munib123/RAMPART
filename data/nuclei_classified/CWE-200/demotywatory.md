# Vulnerability: Demotywatory User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`demotywatory.yaml`)

## Description
Demotywatory user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://demotywatory.pl/user/{{user}}
```

