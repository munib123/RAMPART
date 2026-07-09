# Nuclei Template: OpenShift Assisted Installer Panel - Detect
**Template ID:** openshift-installer-panel
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Medium
**CWE:** CWE-284
**Source:** Nuclei Template (`openshift-installer-panel.yaml`)

## Vulnerability Information & PoC

## Description
OpenShift Assisted Installer panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/clusters
```

