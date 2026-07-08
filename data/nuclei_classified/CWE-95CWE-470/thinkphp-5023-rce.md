# Vulnerability: ThinkPHP 5.0.23 - Remote Code Execution
**Classification:** CWE-95,CWE-470
**Source:** Nuclei Template (`thinkphp-5023-rce.yaml`)

## Description
ThinkPHP 5.0.23 is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/index.php?s=captcha
```

