# Vulnerability: Google Earth Enterprise Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`google-earth-dlogin.yaml`)

## Description
Google Earth Enterprise default login credentials were discovered.

## Secure Mitigation
To reset the username and password:

sudo /opt/google/gehttpd/bin/htpasswd -c
/opt/google/gehttpd/conf.d/.htpasswd geapacheuse"

## Vulnerable Code Pattern / Exploit Payload
```http
GET /admin/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

