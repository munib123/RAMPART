# Vulnerability: Github Workflow Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`github-workflows-disclosure.yaml`)

## Description
Github Workflow was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

