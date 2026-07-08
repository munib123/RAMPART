# Vulnerability: Apache Tomcat - Snoop Servlet Information Disclosure
**Classification:** APACHE
**Source:** Nuclei Template (`tomcat-snoop-servlet-exposed.yaml`)

## Description
The Snoop servlet is exposed in the Apache Tomcat examples directory.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/examples/jsp/snp/snoop.jsp
```

