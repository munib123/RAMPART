# Vulnerability: DBeaver - Credentials Discovery
**Classification:** CWE-522
**Source:** Nuclei Template (`dbeaver-credentials.yaml`)

## Description
DBeaver credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /{{str}}.json HTTP/1.1
Host: {{Hostname}}

GET /.dbeaver/credentials-config.json HTTP/1.1
Host: {{Hostname}}
```

