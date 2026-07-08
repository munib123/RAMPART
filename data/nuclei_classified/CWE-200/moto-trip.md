# Vulnerability: Moto-trip User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`moto-trip.yaml`)

## Description
Moto-trip user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://moto-trip.com/profil/{{user}}
```

