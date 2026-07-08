# Vulnerability: StoryCorps User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`storycorps.yaml`)

## Description
StoryCorps user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://archive.storycorps.org/user/{{user}}/
```

