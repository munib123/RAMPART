# Vulnerability: GitBook Detect
**Classification:** TECH
**Source:** Nuclei Template (`gitbook-detect.yaml`)

## Description
GitBook is a collaborative documentation tool that allows anyone to document anything—such as products and APIs—and share knowledge through a user-friendly online platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

