# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 568_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `568_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 1-22 of the vulnerable file.

require 'grape/middleware/base'

module Grape
  module Middleware
    class Error < Base
      def default_options
        {
          default_status: 500, # default status returned on error
          default_message: '',
          format: :txt,
          helpers: nil,
          formatters: {},
          error_formatters: {},
          rescue_all: false, # true to rescue all exceptions
          rescue_grape_exceptions: false,
          rescue_subclasses: true, # rescue subclasses of exceptions listed
          rescue_options: {
            backtrace: false, # true to display backtrace, true to let Grape handle Grape::Exceptions
            original_exception: false, # true to display exception
          },
          rescue_handlers: {}, # rescue handler blocks
          base_only_rescue_handlers: {}, # rescue handler blocks rescuing only the base class
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 require 'grape/middleware/base'
+require 'active_support/core_ext/string/output_safety'
 
 module Grape
   module Middleware
@@ -69,6 +70,9 @@
       end
 
       def rack_response(message, status = options[:default_status], headers = { Grape::Http::Headers::CONTENT_TYPE => content_type })
+        if headers[Grape::Http::Headers::CONTENT_TYPE] == TEXT_HTML
+          message = ERB::Util.html_escape(message)
+        end
         Rack::Response.new([message], status, headers).finish
       end
 
```
