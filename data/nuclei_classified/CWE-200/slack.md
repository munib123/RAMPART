# Vulnerability: Slack User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`slack.yaml`)

## Description
Slack user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.slack.com
```

