# Vulnerability: AVTECH AVC798HA DVR - Information Exposure
**Classification:** DVR
**Source:** Nuclei Template (`avtech-dvr-exposure.yaml`)

## Description
AVTECH AVC798HA DVR is susceptible to information exposure. CGI scripts in the /cgi-bin/nobody directory can be accessed without authentication. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/nobody/Machine.cgi?action=get_capability
```

