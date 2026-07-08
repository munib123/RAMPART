# Vulnerability: Selea Targa IP OCR-ANPR Camera - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`targa-camera-lfi.yaml`)

## Description
Selea Targa IP OCR-ANPR camera suffers from an unauthenticated local file inclusion vulnerability because input passed through the Download Archive in Storage page using get_file.php script is not properly verified before being used to download files. This can be exploited to disclose the contents of arbitrary and sensitive files via directory traversal attacks and aid the attacker in disclosing clear-text credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CFCARD/images/SeleaCamera/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
```

