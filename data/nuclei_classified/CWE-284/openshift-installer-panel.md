# Vulnerability: OpenShift Assisted Installer Panel - Detect
**Classification:** CWE-284
**Source:** Nuclei Template (`openshift-installer-panel.yaml`)

## Description
OpenShift Assisted Installer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/clusters
```

