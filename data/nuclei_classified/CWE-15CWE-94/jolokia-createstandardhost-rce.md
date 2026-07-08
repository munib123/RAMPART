# Vulnerability: Jolokia file write to RCE jfr
**Classification:** CWE-15,CWE-94
**Source:** Nuclei Template (`jolokia-createstandardhost-rce.yaml`)

## Description
File read and file write to RCE by deploying a vhost with MBeanFactory/createStandardHost and DiagnosticCommand/jfrStart

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jolokia/list
```

