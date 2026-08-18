# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in ruby
**Pair ID:** 1925_3
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1925_3`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

module CarrierWave
  module Downloader
    class RemoteFile
      attr_reader :file

      def initialize(file)
        @file = file.is_a?(String) ? StringIO.new(file) : file
      end

      def original_filename
        filename = filename_from_header || filename_from_uri
        mime_type = MiniMime.lookup_by_content_type(file.content_type)
        unless File.extname(filename).present? || mime_type.blank?
          filename = "#{filename}.#{mime_type.extension}"
        end
        filename
      end

      def respond_to?(*args)
        super || file.respond_to?(*args)
      end

      private

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,15 +1,36 @@
 module CarrierWave
   module Downloader
     class RemoteFile
-      attr_reader :file
+      attr_reader :file, :uri
 
       def initialize(file)
-        @file = file.is_a?(String) ? StringIO.new(file) : file
+        case file
+        when String
+          @file = StringIO.new(file)
+        when Net::HTTPResponse
+          @file = StringIO.new(file.body)
+          @content_type = file.content_type
+          @headers = file
+          @uri = file.uri
+        else
+          @file = file
+          @content_type = file.content_type
+          @headers = file.meta
+          @uri = file.base_uri
+        end
+      end
+
+      def content_type
+        @content_type || 'application/octet-stream'
+      end
+
+      def headers
+        @headers || {}
       end
 
       def original_filename
         filename = filename_from_header || filename_from_uri
-        mime_type = MiniMime.lookup_by_content_type(file.content_type)
+        mime_type = MiniMime.lookup_by_content_type(content_type)
         unless File.extname(filename).present? || mime_type.blank?
           filename = "#{filename}.#{mime_type.extension}"
         end
@@ -23,16 +44,16 @@
       private
 
       def filename_from_header
-        return nil unless file.meta.include? 'content-disposition'
+        return nil unless headers['content-disposition']
 
-        match = file.meta['content-disposition'].match(/filename=(?:"([^"]+)"|([^";]+))/)
+        match = headers['content-disposition'].match(/filename=(?:"([^"]+)"|([^";]+))/)
         return nil unless match
 
         match[1].presence || match[2].presence
       end
 
       def filename_from_uri
-        CGI.unescape(File.basename(file.base_uri.path))
+        CGI.unescape(File.basename(uri.path))
       end
 
       def method_missing(*args, &block)
```
