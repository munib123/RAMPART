# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 164_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `164_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 61-101 of the vulnerable file.


    def safe?
      get? or head? or options? or trace?
    end

    def idempotent?
      safe? or put? or delete? or link? or unlink?
    end

    def link?
      request_method == "LINK"
    end

    def unlink?
      request_method == "UNLINK"
    end

    def params
      super
    rescue Rack::Utils::ParameterTypeError, Rack::Utils::InvalidParameterError => e
      raise BadRequest, "Invalid query parameters: #{e.message}"
    end

    private

    class AcceptEntry
      attr_accessor :params
      attr_reader :entry

      def initialize(entry)
        params = entry.scan(HEADER_PARAM).map! do |s|
          key, value = s.strip.split('=', 2)
          value = value[1..-2].gsub(/\\(.)/, '\1') if value.start_with?('"')
          [key, value]
        end

        @entry  = entry
        @type   = entry[/[^;]+/].delete(' ')
        @params = Hash[params]
        @q      = @params.delete('q') { 1.0 }.to_f
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,7 @@
     def params
       super
     rescue Rack::Utils::ParameterTypeError, Rack::Utils::InvalidParameterError => e
-      raise BadRequest, "Invalid query parameters: #{e.message}"
+      raise BadRequest, "Invalid query parameters: #{Rack::Utils.escape_html(e.message)}"
     end
 
     private
```
