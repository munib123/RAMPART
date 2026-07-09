# Nuclei Template: Google Earth Enterprise Default Login
**Template ID:** google-earth-dlogin
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`google-earth-dlogin.yaml`)

## Vulnerability Information & PoC

## Description
Google Earth Enterprise default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /admin/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## Remediation
To reset the username and password:

sudo /opt/google/gehttpd/bin/htpasswd -c
/opt/google/gehttpd/conf.d/.htpasswd geapacheuse"

## References
- https://johnjhacking.com/blog/gee-exploitation/
- https://www.opengee.org/geedocs/5.2.2/answer/3470759.html
