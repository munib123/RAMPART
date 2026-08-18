# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 21_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `21_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-22 of the vulnerable file.

require 'rack/protection'
require 'digest'
require 'logger'
require 'uri'

module Rack
  module Protection
    class Base
      DEFAULT_OPTIONS = {
        :reaction    => :default_reaction, :logging   => true,
        :message     => 'Forbidden',       :encryptor => Digest::SHA1,
        :session_key => 'rack.session',    :status    => 403,
        :allow_empty_referrer => true,
        :report_key           => "protection.failed",
        :html_types           => %w[text/html application/xhtml]
      }

      attr_reader :app, :options

      def self.default_options(options)
        define_method(:default_options) { super().merge(options) }
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 require 'rack/protection'
+require 'rack/utils'
 require 'digest'
 require 'logger'
 require 'uri'
@@ -110,6 +111,10 @@
         options[:encryptor].hexdigest value.to_s
       end
 
+      def secure_compare(a, b)
+        Rack::Utils.secure_compare(a.to_s, b.to_s)
+      end
+
       alias default_reaction deny
 
       def html?(headers)
```
