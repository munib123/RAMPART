# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 5873_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5873_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 13-53 of the vulnerable file.

    def content_type=(mime_type)
      self.headers["Content-Type"] = charset ? "#{mime_type}; charset=#{charset}" : mime_type
    end
    
    def content_type
      content_type = String(headers["Content-Type"] || headers["type"]).split(";")[0]
      content_type.blank? ? nil : content_type
    end
    
    def charset=(encoding)
      self.headers["Content-Type"] = "#{content_type || Mime::HTML}; charset=#{encoding}"
    end
    
    def charset
      charset = String(headers["Content-Type"] || headers["type"]).split(";")[1]
      charset.blank? ? nil : charset.strip.split("=")[1]
    end

    def redirect(to_url, response_status)
      self.headers["Status"] = response_status
      self.headers["Location"] = to_url

      self.body = "<html><body>You are being <a href=\"#{to_url}\">redirected</a>.</body></html>"
    end

    def prepare!
      handle_conditional_get!
      convert_content_type!
      set_content_length!
    end


    private
      def handle_conditional_get!
        if body.is_a?(String) && (headers['Status'] ? headers['Status'][0..2] == '200' : true)  && !body.empty?
          self.headers['ETag'] ||= %("#{Digest::MD5.hexdigest(body)}")
          self.headers['Cache-Control'] = 'private, max-age=0, must-revalidate' if headers['Cache-Control'] == DEFAULT_HEADERS['Cache-Control']

          if request.headers['HTTP_IF_NONE_MATCH'] == headers['ETag']
            self.headers['Status'] = '304 Not Modified'
            self.body = ''
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,9 +30,9 @@
 
     def redirect(to_url, response_status)
       self.headers["Status"] = response_status
-      self.headers["Location"] = to_url
+      self.headers["Location"] = to_url.gsub(/[\r\n]/, '')
 
-      self.body = "<html><body>You are being <a href=\"#{to_url}\">redirected</a>.</body></html>"
+      self.body = "<html><body>You are being <a href=\"#{CGI.escapeHTML(to_url)}\">redirected</a>.</body></html>"
     end
 
     def prepare!
```
