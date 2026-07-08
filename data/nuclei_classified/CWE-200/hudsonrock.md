# Vulnerability: HudsonRock User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hudsonrock.yaml`)

## Description
HudsonRock user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={{user}}
```

