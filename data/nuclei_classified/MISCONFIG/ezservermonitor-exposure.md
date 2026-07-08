# Vulnerability: eZ Server Monitor - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ezservermonitor-exposure.yaml`)

## Description
Detected exposed eZ Server Monitor instances that revealed sensitive server information, including hostname, OS, kernel version, CPU details, memory usage, disk space, network interfaces with IP addresses, service status, and user login history.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/esm/
GET {{BaseURL}}/monitoring/
GET {{BaseURL}}/ezservermonitor/
```

