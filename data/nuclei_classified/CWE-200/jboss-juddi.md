# Vulnerability: JBoss WS JUDDI Console Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jboss-juddi.yaml`)

## Description
The jUDDI (Java Universal Description, Discovery and Integration) Registry is a core component of the JBoss Enterprise SOA Platform. It is the product's default service registry and comes included as part of the product. In it are stored the addresses (end-point references) of all the services connected to the Enterprise Service Bus. It was implemented in JAXR and conforms to the UDDI specifications.

## Secure Mitigation
Restrict access to the service if not needed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/juddi/
```

