# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in ruby
**Pair ID:** 1925_2
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1925_2`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```ruby
Lines 1-22 of the vulnerable file.

require 'open-uri'
require 'addressable'
require 'carrierwave/downloader/remote_file'

module CarrierWave
  module Downloader
    class Base
      attr_reader :uploader

      def initialize(uploader)
        @uploader = uploader
      end

      ##
      # Downloads a file from given URL and returns a RemoteFile.
      #
      # === Parameters
      #
      # [url (String)] The URL where the remote file is stored
      # [remote_headers (Hash)] Request headers
      #
      def download(url, remote_headers = {})
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 require 'open-uri'
+require 'ssrf_filter'
 require 'addressable'
 require 'carrierwave/downloader/remote_file'
 
@@ -22,12 +23,22 @@
       def download(url, remote_headers = {})
         headers = remote_headers.
           reverse_merge('User-Agent' => "CarrierWave/#{CarrierWave::VERSION}")
+        uri = process_uri(url.to_s)
         begin
-          file = OpenURI.open_uri(process_uri(url.to_s), headers)
+          if skip_ssrf_protection?(uri)
+            response = OpenURI.open_uri(process_uri(url.to_s), headers)
+          else
+            request = nil
+            response = SsrfFilter.get(uri, headers: headers) do |req|
+              request = req
+            end
+            response.uri = request.uri
+            response.value
+          end
         rescue StandardError => e
           raise CarrierWave::DownloadError, "could not download file: #{e.message}"
         end
-        CarrierWave::Downloader::RemoteFile.new(file)
+        CarrierWave::Downloader::RemoteFile.new(response)
       end
 
       ##
@@ -49,6 +60,28 @@
       rescue URI::InvalidURIError, Addressable::URI::InvalidURIError
         raise CarrierWave::DownloadError, "couldn't parse URL: #{uri}"
       end
+
+      ##
+      # If this returns true, SSRF protection will be bypassed.
+      # You can override this if you want to allow accessing specific local URIs that are not SSRF exploitable.
+      #
+      # === Parameters
+      #
+      # [uri (URI)] The URI where the remote file is stored
+      #
+      # === Examples
+      #
+      #     class CarrierWave::Downloader::CustomDownloader < CarrierWave::Downloader::Base
+      #       def skip_ssrf_protection?(uri)
+      #         uri.hostname == 'localhost' && uri.port == 80
+      #       end
+      #     end
+      #
+      #     my_uploader.downloader = CarrierWave::Downloader::CustomDownloader
+      #
+      def skip_ssrf_protection?(uri)
+        false
+      end
     end
   end
 end
```
