# Vulnerability: Cisco System Network Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-network-config.yaml`)

## Description
Cisco System Network configuration page was detected. Page lists whole network configuration and internal logs of Cisco IP phones.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CGI/Java/Serviceability?adapter=device.statistics.configuration
```

