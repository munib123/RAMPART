# Vulnerability: Pastebin API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-pastebin.yaml`)

## Description
Plain Text Storage

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://pastebin.com/api/api_post.php HTTP/1.1
Host: pastebin.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 81

api_dev_key={{token}}&api_paste_code=test&api_option=paste
```

