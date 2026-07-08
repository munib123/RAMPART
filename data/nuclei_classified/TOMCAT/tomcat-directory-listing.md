# Vulnerability: Apache Tomcat - Directory Listing Enabled
**Classification:** TOMCAT
**Source:** Nuclei Template (`tomcat-directory-listing.yaml`)

## Description
Directory listing is enabled on the Apache Tomcat server, allowing users to view the contents of web directories.This could lead to unauthorized access to sensitive files and potential information disclosure.

## Secure Mitigation
Disable directory listings by setting the listings parameter to false in the web.xml under the DefaultServlet. This helps prevent unauthorized directory browsing and protects sensitive files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

