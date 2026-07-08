# Vulnerability: Speaker Deck User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`speaker-deck.yaml`)

## Description
Speaker Deck user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://speakerdeck.com/{{user}}/
```

