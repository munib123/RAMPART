# Vulnerability: Woocommerce - PDF Invoice Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`wp-woocommerce-pdf-invoice-listing.yaml`)

## Description
A vulnerability in Woocommerce allows remote unauthenticated attackers to access company invoices and other sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/pdf-invoices/
```

