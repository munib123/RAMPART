# Nuclei Template: Kubernetes Local Cluster Web View Panel- Detect
**Template ID:** kubernetes-web-view
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`kubernetes-web-view.yaml`)

## Vulnerability Information & PoC

## Description
Kubernetes local cluster web view panel discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/clusters/local
```

