# Vulnerability: Joomla! htaccess file disclosure
**Classification:** MISCELLANEOUS
**Source:** Nuclei Template (`joomla-htaccess-file.yaml`)

## Description
Joomla!  has an htaccess file to store configurations about HTTP config, directory listing, etc.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/htaccess.txt
```

