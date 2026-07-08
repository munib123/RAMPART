# Vulnerability: Prometheus targets API endpoint
**Classification:** PROMETHEUS
**Source:** Nuclei Template (`prometheus-targets.yaml`)

## Description
The targets endpoint exposes services belonging to the infrastructure, including their roles and labels. In addition to showing the target machine addresses, the endpoint also exposes metadata labels that are added by the target provider. These labels are intended to contain non-sensitive values, like the name of the server or its description, but various cloud platforms may automatically expose sensitive data in these labels, oftentimes without the developer's knowledge.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/targets
```

