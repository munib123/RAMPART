# Vulnerability: GraphQL CSRF / GET method
**Classification:** GRAPHQL
**Source:** Nuclei Template (`graphql-get-method.yaml`)

## Description
Cross Site Request Forgery happens when an external website gains ability to make API calls impersonating an user if he visits the website while being authenticated to your API.
Allowing API calls through GET requests can lead to CSRF attacks, because cookies are added automatically to GET requests by the browser.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/graphql?query={__typename}
GET {{BaseURL}}/api/graphql?query={__typename}
```

