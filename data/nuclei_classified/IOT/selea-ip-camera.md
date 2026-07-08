# Vulnerability: Detect Selea Targa IP OCR-ANPR Camera
**Classification:** IOT
**Source:** Nuclei Template (`selea-ip-camera.yaml`)

## Description
Various version of the Selea Targa IP OCR-ANPR Camera are vulnerable to an Unauthenticated RTP/RTSP/M-JPEG Stream Disclosure flaw

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

