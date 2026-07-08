# Vulnerability: Apache Tomcat Example Scripts - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tomcat-scripts.yaml`)

## Description
Multiple Apache Tomcat example scripts were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/examples/servlets/index.html
GET {{BaseURL}}/examples/jsp/index.html
GET {{BaseURL}}/examples/websocket/index.xhtml
GET {{BaseURL}}/examples/servlets/servlet/SessionExample
GET {{BaseURL}}/..;/examples/servlets/index.html
GET {{BaseURL}}/..;/examples/jsp/index.html
GET {{BaseURL}}/..;/examples/websocket/index.xhtml
GET {{BaseURL}}/..;/examples/servlets/servlet/SessionExample
```

