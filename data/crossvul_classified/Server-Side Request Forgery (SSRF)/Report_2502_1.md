# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in ruby
**Pair ID:** 2502_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2502_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```ruby
Lines 26-66 of the vulnerable file.


        METHODS = {
          :head   => ::Net::HTTP::Head,
          :get    => ::Net::HTTP::Get,
          :post   => ::Net::HTTP::Post,
          :put    => ::Net::HTTP::Put,
          :delete => ::Net::HTTP::Delete
        }

        def request method, uri, options = {}
          head = headers.dup
          head.update options[:head] if options[:head]
          head.delete_if { |_, value| value.nil? }
          uri = base_uri + uri
          if options[:params] && !options[:params].empty?
            pairs = options[:params].map { |key, value|
              "#{CGI.escape key.to_s}=#{CGI.escape value.to_s}"
            }
            uri += "?#{pairs.join '&'}"
          end
          request = METHODS[method].new uri.request_uri, head
          request.basic_auth(*[Recurly.api_key, nil].flatten[0, 2])
          if options[:body]
            request['Content-Type'] = content_type
            request.body = options[:body]
          end
          if options[:etag]
            request['If-None-Match'] = options[:etag]
          end
          if options[:format]
            request['Accept'] = FORMATS[options[:format]]
          end
          if options[:locale]
            request['Accept-Language'] = options[:locale]
          end
          http = ::Net::HTTP.new uri.host, uri.port
          http.use_ssl = uri.scheme == 'https'
          net_http.each_pair { |key, value| http.send "#{key}=", value }

          if Recurly.logger
            Recurly.log :info, "===> %s %s" % [request.method, uri]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,6 +43,7 @@
             }
             uri += "?#{pairs.join '&'}"
           end
+          self.validate_uri!(uri)
           request = METHODS[method].new uri.request_uri, head
           request.basic_auth(*[Recurly.api_key, nil].flatten[0, 2])
           if options[:body]
```
