# Vulnerability: Atlassian Bamboo Setup Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`atlassian-bamboo-setup-wizard.yaml`)

## Description
Atlassian Bamboo is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/setupLicense.action
```

