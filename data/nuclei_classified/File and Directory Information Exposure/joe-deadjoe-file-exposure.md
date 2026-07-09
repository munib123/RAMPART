# Nuclei Template: Joe Editor DEADJOE File - Exposure
**Template ID:** joe-deadjoe-file-exposure
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Low
**CWE:** CWE-538
**Source:** Nuclei Template (`joe-deadjoe-file-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Deadjoe file,this file was created by Joe's Own Editor when a session terminated abnormally. It contained the full contents of the file being edited at the time of the crash, potentially exposing sensitive information such as passwords, configuration files, or credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/DEADJOE
```

## References
- https://www.acunetix.com/vulnerabilities/web/joe-editor-deadjoe-file/
- https://www.invicti.com/web-application-vulnerabilities/joe-editor-deadjoe-file
- https://www.freebsd.org/security/advisories/FreeBSD-SA-01:04.joe.asc
