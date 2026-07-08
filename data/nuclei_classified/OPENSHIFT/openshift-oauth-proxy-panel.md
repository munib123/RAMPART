# Vulnerability: OpenShift OAuth Proxy - Panel Detect
**Classification:** OPENSHIFT
**Source:** Nuclei Template (`openshift-oauth-proxy-panel.yaml`)

## Description
Detects OpenShift OAuth Proxy login endpoints via `_oauth_proxy_csrf` or `_oauth_proxy` cookie and login page content. Checks both the default port and port 9001.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{RootURL}}:9001
```

