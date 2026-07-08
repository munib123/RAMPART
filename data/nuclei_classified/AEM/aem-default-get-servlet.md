# Vulnerability: AEM DefaultGetServlet
**Classification:** AEM
**Source:** Nuclei Template (`aem-default-get-servlet.yaml`)

## Description
Sensitive information might be exposed via AEM DefaultGetServlet.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

