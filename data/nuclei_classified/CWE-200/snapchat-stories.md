# Vulnerability: Snapchat Stories User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`snapchat-stories.yaml`)

## Description
Snapchat Stories user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://story.snapchat.com/s/{{user}}
```

