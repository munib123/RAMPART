# Vulnerability: Jolokia Configuration - Exposure
**Classification:** CONFIG
**Source:** Nuclei Template (`jolokia-config-exposure.yaml`)

## Description
Detected exposed Jolokia configuration files (jolokia-agent.properties and jolokia-access.xml). Exposure of these files could have revealed sensitive agent configuration, authentication credentials, or access control policies (CORS, allowed MBeans).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jolokia-agent.properties
GET {{BaseURL}}/jolokia-access.xml
GET {{BaseURL}}/WEB-INF/classes/jolokia-agent.properties
GET {{BaseURL}}/WEB-INF/classes/jolokia-access.xml
```

