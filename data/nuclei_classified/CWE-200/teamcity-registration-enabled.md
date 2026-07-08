# Vulnerability: JetBrains TeamCity - Registration Enabled
**Classification:** CWE-200
**Source:** Nuclei Template (`teamcity-registration-enabled.yaml`)

## Description
JetBrains TeamCity allows all visitors to register due to a misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /registerUser.html?init=1 HTTP/1.1
Host: {{Hostname}}
```

