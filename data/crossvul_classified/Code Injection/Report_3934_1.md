# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 3934_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3934_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 1773-1813 of the vulnerable file.


The maximum number of redirect to follow before raising an
exception is 'redirections. The default is 5.

The return value is a tuple of (response, content), the first
being and instance of the 'Response' class, the second being
a string that contains the response entity body.
        """
        conn_key = ''

        try:
            if headers is None:
                headers = {}
            else:
                headers = self._normalize_headers(headers)

            if "user-agent" not in headers:
                headers["user-agent"] = "Python-httplib2/%s (gzip)" % __version__

            uri = iri2uri(uri)

            (scheme, authority, request_uri, defrag_uri) = urlnorm(uri)

            conn_key = scheme + ":" + authority
            conn = self.connections.get(conn_key)
            if conn is None:
                if not connection_type:
                    connection_type = SCHEME_TO_CONNECTION[scheme]
                certs = list(self.certificates.iter(authority))
                if issubclass(connection_type, HTTPSConnectionWithTimeout):
                    if certs:
                        conn = self.connections[conn_key] = connection_type(
                            authority,
                            key_file=certs[0][0],
                            cert_file=certs[0][1],
                            timeout=self.timeout,
                            proxy_info=self.proxy_info,
                            ca_certs=self.ca_certs,
                            disable_ssl_certificate_validation=self.disable_ssl_certificate_validation,
                            tls_maximum_version=self.tls_maximum_version,
                            tls_minimum_version=self.tls_minimum_version,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1790,6 +1790,9 @@
                 headers["user-agent"] = "Python-httplib2/%s (gzip)" % __version__
 
             uri = iri2uri(uri)
+            # Prevent CWE-75 space injection to manipulate request via part of uri.
+            # Prevent CWE-93 CRLF injection to modify headers via part of uri.
+            uri = uri.replace(" ", "%20").replace("\r", "%0D").replace("\n", "%0A")
 
             (scheme, authority, request_uri, defrag_uri) = urlnorm(uri)
 
```
