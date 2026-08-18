# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in ruby
**Pair ID:** 2502_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2502_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```ruby
Lines 1-38 of the vulnerable file.

module Recurly
  # The API class handles all requests to the Recurly API. While most of its
  # functionality is leveraged by the Resource class, it can be used directly,
  # as well.
  #
  # Requests are made with methods named after the four main HTTP verbs
  # recognized by the Recurly API.
  #
  # @example
  #   Recurly::API.get 'accounts'             # => #<Net::HTTPOK ...>
  #   Recurly::API.post 'accounts', xml_body  # => #<Net::HTTPCreated ...>
  #   Recurly::API.put 'accounts/1', xml_body # => #<Net::HTTPOK ...>
  #   Recurly::API.delete 'accounts/1'        # => #<Net::HTTPNoContent ...>
  class API
    require 'recurly/api/errors'

    @@base_uri = "https://api.recurly.com/v2/"

    RECURLY_API_VERSION = '2.8'

    FORMATS = Helper.hash_with_indifferent_read_access(
      'pdf' => 'application/pdf',
      'xml' => 'application/xml'
    )

    class << self
      # Additional HTTP headers sent with each API call
      # @return [Hash{String => String}]
      def headers
        @headers ||= { 'Accept' => accept, 'User-Agent' => user_agent, 'X-Api-Version' => RECURLY_API_VERSION }
      end

      # @return [String, nil] Accept-Language header value
      def accept_language
        headers['Accept-Language']
      end

      # @param [String] language Accept-Language header value
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
     require 'recurly/api/errors'
 
     @@base_uri = "https://api.recurly.com/v2/"
+    @@valid_domains = [".recurly.com"]
 
     RECURLY_API_VERSION = '2.8'
 
@@ -75,6 +76,13 @@
         URI.parse @@base_uri.sub('api', Recurly.subdomain)
       end
 
+      def validate_uri!(uri)
+        domain = @@valid_domains.detect { |d| uri.host.end_with?(d) }
+        unless domain
+          raise ArgumentError, "URI #{uri} is invalid. You may only make requests to a Recurly domain."
+        end
+      end
+
       # @return [String]
       def user_agent
         "Recurly/#{Version}; #{RUBY_DESCRIPTION}"
```
