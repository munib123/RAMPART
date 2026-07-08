# Vulnerability: Apache Tomcat Manager Path Normalization Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apache-tomcat-manager-path-normalization.yaml`)

## Description
Apache Tomcat Manager Path Normalization login panel was discovered via path normalization. Normalizing a path involves modifying the string that identifies a path or file so that it conforms to a valid path on the target operating system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/..;/manager/html
GET {{BaseURL}}/..;/..;/manager/html;/
GET {{BaseURL}}/..;/host-manager/html
GET {{BaseURL}}/..;/..;/host-manager/html;/
GET {{BaseURL}}/{{randstr}}/..;/manager/html
GET {{BaseURL}}/{{randstr}}/..;/host-manager/html
```

