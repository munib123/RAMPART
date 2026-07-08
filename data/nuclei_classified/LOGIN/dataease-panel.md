# Vulnerability: Dataease - Login Panel
**Classification:** LOGIN
**Source:** Nuclei Template (`dataease-panel.yaml`)

## Description
Dataease Login Panel is discovered

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login?redirect=%2F
```

