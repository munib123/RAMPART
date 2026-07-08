# Vulnerability: TestRail Installation Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`testrail-install.yaml`)

## Description
TestRail is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?/installer
```

