# CrossVul Fix Pair: Resource Management Errors in ruby
**Pair ID:** 5599_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5599_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```ruby
Lines 1-33 of the vulnerable file.

require 'net/http'
require 'openid'
require 'openid/util'

begin
  require 'net/https'
rescue LoadError
  OpenID::Util.log('WARNING: no SSL support found.  Will not be able ' +
                   'to fetch HTTPS URLs!')
  require 'net/http'
end

MAX_RESPONSE_KB = 1024

module Net
  class HTTP
    def post_connection_check(hostname)
      check_common_name = true
      cert = @socket.io.peer_cert
      cert.extensions.each { |ext|
        next if ext.oid != "subjectAltName"
        ext.value.split(/,\s+/).each{ |general_name|
          if /\ADNS:(.*)/ =~ general_name
            check_common_name = false
            reg = Regexp.escape($1).gsub(/\\\*/, "[^.]+")
            return true if /\A#{reg}\z/i =~ hostname
          elsif /\AIP Address:(.*)/ =~ general_name
            check_common_name = false
            return true if $1 == hostname
          end
        }
      }
      if check_common_name
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,7 @@
   require 'net/http'
 end
 
-MAX_RESPONSE_KB = 1024
+MAX_RESPONSE_KB = 10485760 # 10 MB (can be smaller, I guess)
 
 module Net
   class HTTP
@@ -192,6 +192,16 @@
         conn = make_connection(url)
         response = nil
 
+        whole_body = ''
+        body_size_limitter = lambda do |r|
+          r.read_body do |partial|   # read body now
+            whole_body << partial
+            if whole_body.length > MAX_RESPONSE_KB
+              raise FetchingError.new("Response Too Large")
+            end
+          end
+          whole_body
+        end
         response = conn.start {
           # Check the certificate against the URL's hostname
           if supports_ssl?(conn) and conn.use_ssl?
@@ -199,13 +209,12 @@
           end
 
           if body.nil?
-            conn.request_get(url.request_uri, headers)
+            conn.request_get(url.request_uri, headers, &body_size_limitter)
           else
             headers["Content-type"] ||= "application/x-www-form-urlencoded"
-            conn.request_post(url.request_uri, body, headers)
+            conn.request_post(url.request_uri, body, headers, &body_size_limitter)
           end
         }
-        setup_encoding(response)
       rescue Timeout::Error => why
         raise FetchingError, "Error fetching #{url}: #{why}"
       rescue RuntimeError => why
@@ -232,7 +241,10 @@
           raise FetchingError, "Error encountered in redirect from #{url}: #{why}"
         end
       else
-        return HTTPResponse._from_net_response(response, unparsed_url)
+        response = HTTPResponse._from_net_response(response, unparsed_url)
+        response.body = whole_body
+        setup_encoding(response)
+        return response
       end
     end
 
```
