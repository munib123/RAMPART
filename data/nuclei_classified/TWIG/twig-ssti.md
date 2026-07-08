# Vulnerability: Twig - Server Side Template Injection
**Classification:** TWIG
**Source:** Nuclei Template (`twig-ssti.yaml`)

## Description
Twig, a PHP template engine, posed significant challenges in crafting a working payload due to its built-in and default configurations, particularly in string creation. However, by utilizing the block feature and the built-in _charset variable, Attacker successfully developed a payload by nesting these elements together.

