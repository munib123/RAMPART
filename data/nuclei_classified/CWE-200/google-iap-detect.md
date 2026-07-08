# Vulnerability: Google Identity-Aware Proxy (IAP) - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`google-iap-detect.yaml`)

## Description
Detected whether the target was protected by Google's Identity-Aware Proxy (IAP). IAP provided application-level access control for services running on Google Cloud. When IAP intercepted an unauthenticated request, it set the X-Goog-Iap-Generated-Response header and redirected the request to Google OAuth. The second request followed the redirects to the consent screen and extracted the OAuth client_id, application owner, contact email, and display name.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}
```

