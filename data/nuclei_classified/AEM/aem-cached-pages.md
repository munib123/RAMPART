# Vulnerability: Invalidate / Flush Cached Pages on AEM
**Classification:** AEM
**Source:** Nuclei Template (`aem-cached-pages.yaml`)

## Description
Cached Pages on AEM can be Flushed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dispatcher/invalidate.cache
```

