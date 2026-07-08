# Vulnerability: Springboot Actuator integrationgraph
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-integrationgraph.yaml`)

## Description
The integrationgraph endpoint exposes a graph containing all Spring Integration components.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/integrationgraph
GET {{BaseURL}}/actuator/integrationgraph
```

