# Vulnerability: Disable Apache2 HTTP TRACE Method
**Classification:** AUDIT
**Source:** Nuclei Template (`file-disable-http-trace-method.yaml`)

## Description
The HTTP TRACE method should be disabled to prevent Cross-Site Tracing (XST) attacks.

## Secure Mitigation
Add 'TraceEnable Off' in the Apache configuration file and restart the service.

