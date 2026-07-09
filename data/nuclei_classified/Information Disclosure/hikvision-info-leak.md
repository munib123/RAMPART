# Nuclei Template: Hikvision Configuration File - Detect
**Template ID:** hikvision-info-leak
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`hikvision-info-leak.yaml`)

## Vulnerability Information & PoC

## Description
Hikvision configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config/user.xml
```

