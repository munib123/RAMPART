# Vulnerability: Atlassian JIRA Setup - Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`jira-setup.yaml`)

## Description
Atlassian JIRA is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/secure/SetupMode!default.jspa
```

