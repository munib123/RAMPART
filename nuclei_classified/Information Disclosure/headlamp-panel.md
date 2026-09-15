# Nuclei Template: Headlamp Kubernetes UI Panel - Detect
**Template ID:** headlamp-panel
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`headlamp-panel.yaml`)

## Vulnerability Information & PoC

## Description
Detected Headlamp Kubernetes Web UI panel exposed, which could lead to unauthorized access to Kubernetes cluster management if not properly secured.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/settings/plugins
GET {{BaseURL}}/settings/cluster
```

## References
- https://headlamp.dev/
- https://github.com/kubernetes-sigs/headlamp
