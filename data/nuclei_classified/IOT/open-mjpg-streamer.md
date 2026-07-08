# Vulnerability: open-mjpg-streamer
**Classification:** IOT
**Source:** Nuclei Template (`open-mjpg-streamer.yaml`)

## Description
Open mjpg-streamer service sharing webcam/camera feed

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?action=stream
```

