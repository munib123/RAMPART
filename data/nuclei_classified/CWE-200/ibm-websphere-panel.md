# Vulnerability: IBM WebSphere Portal Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ibm-websphere-panel.yaml`)

## Description
IBM WebSphere Portal login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{RootURL}}/wps/portal
```

