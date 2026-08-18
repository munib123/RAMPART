# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in ruby
**Pair ID:** 735_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `735_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```ruby
Lines 1-35 of the vulnerable file.

require 'oj'

module Slanger
  module Api
    class RequestValidation < Struct.new :raw_body, :raw_params, :path_info
      def initialize(*args)
        super(*args)

        validate!
        authenticate!
        parse_body!
      end

      def data
        @data ||= Oj.load(body["data"] || params["data"])
      end

      def body
        @body ||= validate_body!
      end

      def auth_params
        params.except('channel_id', 'app_id')
      end

      def socket_id
        @socket_id ||= determine_valid_socket_id
      end

      def params
        @params ||= validate_raw_params!
      end

      def channels
        @channels ||= Array(body["channels"] || params["channels"])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,7 @@
       end
 
       def data
-        @data ||= Oj.load(body["data"] || params["data"])
+        @data ||= Oj.strict_load(body["data"] || params["data"])
       end
 
       def body
@@ -87,7 +87,7 @@
       end
 
       def assert_valid_json!(string)
-        Oj.load(string)
+        Oj.strict_load(string)
       rescue Oj::ParserError
         raise Slanger::InvalidRequest.new("Invalid request body: #{raw_body}")
       end
```
