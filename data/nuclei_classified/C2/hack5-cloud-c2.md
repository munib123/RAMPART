# Vulnerability: Hack5 Cloud C2 - Detect
**Classification:** C2
**Source:** Nuclei Template (`hack5-cloud-c2.yaml`)

## Description
Cloud C² is a self-hosted web-based command and control suite for networked Hak5 gear that lets you pentest from anywhere. Linux, Mac and Windows computers can host the Cloud C² server while Hak5 gear such as the WiFi Pineapple, LAN Turtle and Packet Squirrel can be provisioned as clients.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

