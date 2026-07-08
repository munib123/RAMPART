# Vulnerability: TMDB User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tmdb.yaml`)

## Description
TMDB user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.themoviedb.org/u/{{user}}
```

