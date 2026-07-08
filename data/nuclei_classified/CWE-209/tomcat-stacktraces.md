# Vulnerability: Tomcat Stack Traces Enabled
**Classification:** CWE-209
**Source:** Nuclei Template (`tomcat-stacktraces.yaml`)

## Description
Examine whether Tomcat stack traces are turned on by employing a designated problematic pattern.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?f=\[
```

