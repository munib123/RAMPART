# Nuclei Template: Kubernetes Kustomize Configuration - Detect
**Template ID:** kubernetes-kustomization-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`kubernetes-kustomization-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Kubernetes Kustomize configuration was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/kustomization.yml
```

## References
- https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/kubernetes-kustomization-disclosure.json
