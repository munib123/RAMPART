# Vulnerability: KnowledgeTree Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`knowledgetree-installer.yaml`)

## Description
KnowledgeTree is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/wizard/
```

