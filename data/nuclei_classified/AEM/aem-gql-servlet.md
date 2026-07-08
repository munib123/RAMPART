# Vulnerability: AEM GQLServlet
**Classification:** AEM
**Source:** Nuclei Template (`aem-gql-servlet.yaml`)

## Description
AEM GQLServlet is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

