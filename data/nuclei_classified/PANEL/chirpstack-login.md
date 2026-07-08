# Vulnerability: ChirpStack LoRaWAN Detection
**Classification:** PANEL
**Source:** Nuclei Template (`chirpstack-login.yaml`)

## Description
Detects the presence of ChirpStack LoRaWAN Network-Server by identifying unique page characteristics in the HTML response.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

