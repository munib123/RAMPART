# Vulnerability: Deep Sea Electronics DSE 855 Generator Controller - Detect
**Classification:** TECH
**Source:** Nuclei Template (`deep-sea-electronics-dse855-detect.yaml`)

## Description
Deep Sea Electronics DSE 855 is a generator/mains automatic transfer switch (ATS) controller
with a built-in HTTP web server for remote monitoring and configuration of generator control systems.
The interface is commonly exposed on port 8090 and requires no authentication by default.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

