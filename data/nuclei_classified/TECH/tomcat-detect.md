# Vulnerability: Tomcat Detection
**Classification:** TECH
**Source:** Nuclei Template (`tomcat-detect.yaml`)

## Description
If an Tomcat instance is deployed on the target URL, when we send a request for a non existent resource we receive a Tomcat error page with version.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/{{randstr}}
GET {{BaseURL}}/docs/introduction.html
GET {{BaseURL}}/\
```

