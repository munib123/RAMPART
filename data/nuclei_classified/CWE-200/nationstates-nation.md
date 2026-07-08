# Vulnerability: NationStates Nation User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nationstates-nation.yaml`)

## Description
NationStates Nation user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://nationstates.net/nation={{user}}
```

