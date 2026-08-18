# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 2939_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2939_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 1-23 of the vulnerable file.

require 'sinatra/base'
require 'thin'

module Gemirro
  ##
  # Launch Sinatra server to easily download gems.
  #
  class Server < Sinatra::Base
    # rubocop:disable Metrics/LineLength
    URI_REGEXP = /^(.*)-(\d+(?:\.\d+){1,4}.*?)(?:-(x86-(?:(?:mswin|mingw)(?:32|64)).*?|java))?\.(gem(?:spec\.rz)?)$/
    GEMSPEC_TYPE = 'gemspec.rz'.freeze
    GEM_TYPE = 'gem'.freeze

    access_logger = Logger.new(Utils.configuration.server.access_log).tap do |logger|
      ::Logger.class_eval { alias_method :write, :'<<' }
      logger.level = ::Logger::INFO
    end
    # rubocop:enable Metrics/LineLength

    error_logger = File.new(Utils.configuration.server.error_log, 'a+')
    error_logger.sync = true

    before do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 require 'sinatra/base'
 require 'thin'
+require 'uri'
 
 module Gemirro
   ##
@@ -271,6 +272,16 @@
       def escape(string)
         Rack::Utils.escape_html(string)
       end
+
+      ##
+      # Homepage link
+      #
+      # @param [Gem] spec
+      # @return [String]
+      #
+      def homepage(spec)
+        URI.parse(URI.escape(spec.homepage))
+      end
     end
   end
 end
```
