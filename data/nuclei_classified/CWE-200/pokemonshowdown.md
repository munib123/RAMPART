# Vulnerability: Pokemonshowdown User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pokemonshowdown.yaml`)

## Description
Pokemonshowdown user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pokemonshowdown.com/users/{{user}}
```

