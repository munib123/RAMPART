# Vulnerability: wordpress-upload-data
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-upload-data.yaml`)

## Description
The remote WordPress installation contains a file 'data.txt' under the '/wp-content/uploads/' folder that has sensitive information inside it.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/data.txt
```

