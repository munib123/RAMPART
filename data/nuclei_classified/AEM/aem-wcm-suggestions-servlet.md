# Vulnerability: AEM WCM Suggestions Servlet
**Classification:** AEM
**Source:** Nuclei Template (`aem-wcm-suggestions-servlet.yaml`)

## Description
AEM WCM Suggestions Servlet is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bin/wcm/contentfinder/connector/suggestions.json;%0aOJh.css?query_term=path%3a/&pre={{randstr}}
```

