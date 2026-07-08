# Vulnerability: OpenEMR - Default Admin Discovery
**Classification:** CWE-522
**Source:** Nuclei Template (`openemr-default-login.yaml`)

## Description
OpenEMR default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /interface/main/main_screen.php?auth=login&site=default HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_login_session_management=1&languageChoice=1&authUser={{user}}&clearPass={{pass}}&languageChoice=10
```

