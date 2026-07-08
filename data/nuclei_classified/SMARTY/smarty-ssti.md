# Vulnerability: Smarty - Server Side Template Injection
**Classification:** SMARTY
**Source:** Nuclei Template (`smarty-ssti.yaml`)

## Description
In PHP template engine Smarty, template injection is possible by exploiting the passthru function combined with array_map and chr.

