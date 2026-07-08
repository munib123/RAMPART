# Vulnerability: LabVIEW/NI Service Locator
**Classification:** DETECT
**Source:** Nuclei Template (`labview-service-locator-enum.yaml`)

## Description
National Instruments (LabVIEW) Service Locator detected and enumerated. This services leaks a list of all services provided by the device, hardware capabilities and possibly versions. These hardware devices should not be exposed to the internet.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dumpinfo
```

