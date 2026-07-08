# Vulnerability: Zzzcms 1.75 - Information Disclosure
**Classification:** ZZZCMS
**Source:** Nuclei Template (`zzzcms-info-disclosure.yaml`)

## Description
There is a rather strange file that directly echoes some content belonging to the inaccessible zzz_config.php. The information leakage file is located in plugins\webuploader\js\webconfig.php, and the management path name of the management background can be obtained directly. No need to blast admin and add 3 digits anymore

## Vulnerable Code Pattern / Exploit Payload
```http
GET /plugins/webuploader/js/webconfig.php HTTP/1.1
Host: {{Hostname}}
```

