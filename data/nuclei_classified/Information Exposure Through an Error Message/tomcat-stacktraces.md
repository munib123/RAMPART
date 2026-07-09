# Nuclei Template: Tomcat Stack Traces Enabled
**Template ID:** tomcat-stacktraces
**Vulnerability Class:** Information Exposure Through an Error Message
**Severity:** Low
**CWE:** CWE-209
**Source:** Nuclei Template (`tomcat-stacktraces.yaml`)

## Vulnerability Information & PoC

## Description
Examine whether Tomcat stack traces are turned on by employing a designated problematic pattern.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?f=\[
```

