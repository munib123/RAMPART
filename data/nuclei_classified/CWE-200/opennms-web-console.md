# Vulnerability: OpenNMS Web Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`opennms-web-console.yaml`)

## Description
OpenNMS Web Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/opennms/login.jsp
```

