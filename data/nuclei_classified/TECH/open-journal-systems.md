# Vulnerability: Open Journal Systems Detect
**Classification:** TECH
**Source:** Nuclei Template (`open-journal-systems.yaml`)

## Description
Open Journal Systems, also known as OJS, is a free software for the management of peer-reviewed academic journals, created by the Public Knowledge Project.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

