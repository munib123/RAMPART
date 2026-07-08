# Vulnerability: Apache Struts Dev Mode - Detect
**Classification:** STRUTS
**Source:** Nuclei Template (`struts-problem-report.yaml`)

## Description
Multiple Apache Struts applications were detected in dev-mode.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

