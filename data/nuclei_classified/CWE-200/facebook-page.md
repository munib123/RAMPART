# Vulnerability: Facebook Page Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`facebook-page.yaml`)

## Description
Facebook Page name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://facebook.com/{{user}} HTTP/1.1
Host: www.facebook.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Sec-Fetch-Mode: navigate
Accept-Language: en-US,en;q=0.9
```

