# Vulnerability: SportyBet / BetKing Admin or API Token - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`sportybet-api.yaml`)

## Description
Detected exposed internal tokens and administrative endpoints belonging to online betting platforms.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

