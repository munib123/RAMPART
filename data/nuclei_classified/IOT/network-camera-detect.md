# Vulnerability: Various Online Devices Detection (Network Camera)
**Classification:** IOT
**Source:** Nuclei Template (`network-camera-detect.yaml`)

## Description
Network camera panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CgiStart?page=Single
```

