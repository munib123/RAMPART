# Vulnerability: AnimePlanet User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`animeplanet.yaml`)

## Description
AnimePlanet user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.anime-planet.com/users/{{user}}
```

