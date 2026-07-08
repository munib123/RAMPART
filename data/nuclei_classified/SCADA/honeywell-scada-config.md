# Vulnerability: Honeywell Scada Configuration File - Detect
**Classification:** SCADA
**Source:** Nuclei Template (`honeywell-scada-config.yaml`)

## Description
Honeywell Scada configuration file was detected. The downloaded file opens with the file name and contains critical information about the destination address.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web_caps/webCapsConfig
```

