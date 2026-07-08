# Vulnerability: Twitch User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`twitch.yaml`)

## Description
Twitch user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://twitchtracker.com/search?q={{user}}
```

