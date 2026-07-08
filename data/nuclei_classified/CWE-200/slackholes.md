# Vulnerability: SlackHoles User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`slackholes.yaml`)

## Description
SlackHoles user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://slackholes.com/actor/{{user}}/
```

