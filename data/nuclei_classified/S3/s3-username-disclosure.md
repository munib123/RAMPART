# Vulnerability: x-amz-meta-s3cmd-attrs Header Username Disclosure
**Classification:** S3
**Source:** Nuclei Template (`s3-username-disclosure.yaml`)

## Description
Detected exposure of the x-amz-meta-s3cmd-attrs header in S3 objects, which can disclose sensitive information including the username (uname), user ID (uid), group name (gname), and group ID (gid) of the user who uploaded the file using s3cmd.

## Secure Mitigation
Use s3cmd with --no-preserve flag or set preserve_attrs = False in s3cmd configuration to prevent storing filesystem attributes in S3 object metadata.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

