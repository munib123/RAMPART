# Vulnerability: Ilovegrowingmarijuana User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ilovegrowingmarijuana.yaml`)

## Description
Ilovegrowingmarijuana user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://support.ilovegrowingmarijuana.com/u/{{user}}
```

