# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 4551_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4551_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 211-243 of the vulnerable file.


    CLOSE = "close".freeze
    KEEP_ALIVE = "keep-alive".freeze

    CONTENT_LENGTH2 = "content-length".freeze
    CONTENT_LENGTH_S = "Content-Length: ".freeze
    TRANSFER_ENCODING = "transfer-encoding".freeze
    TRANSFER_ENCODING2 = "HTTP_TRANSFER_ENCODING".freeze

    CONNECTION_CLOSE = "Connection: close\r\n".freeze
    CONNECTION_KEEP_ALIVE = "Connection: Keep-Alive\r\n".freeze

    TRANSFER_ENCODING_CHUNKED = "Transfer-Encoding: chunked\r\n".freeze
    CLOSE_CHUNKED = "0\r\n\r\n".freeze

    CHUNKED = "chunked".freeze

    COLON = ": ".freeze

    NEWLINE = "\n".freeze
    CRLF_REGEX = /[\r\n]/.freeze

    HIJACK_P = "rack.hijack?".freeze
    HIJACK = "rack.hijack".freeze
    HIJACK_IO = "rack.hijack_io".freeze

    EARLY_HINTS = "rack.early_hints".freeze

    # Mininum interval to checks worker health
    WORKER_CHECK_INTERVAL = 5

  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -228,7 +228,7 @@
     COLON = ": ".freeze
 
     NEWLINE = "\n".freeze
-    CRLF_REGEX = /[\r\n]/.freeze
+    HTTP_INJECTION_REGEX = /[\r\n]/.freeze
 
     HIJACK_P = "rack.hijack?".freeze
     HIJACK = "rack.hijack".freeze
```
