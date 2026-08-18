# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5597_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5597_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 1-22 of the vulnerable file.

module HTTParty
  # The default parser used by HTTParty, supports xml, json, html, yaml, and
  # plain text.
  #
  # == Custom Parsers
  #
  # If you'd like to do your own custom parsing, subclassing HTTParty::Parser
  # will make that process much easier. There are a few different ways you can
  # utilize HTTParty::Parser as a superclass.
  #
  # @example Intercept the parsing for all formats
  #   class SimpleParser < HTTParty::Parser
  #     def parse
  #       perform_parsing
  #     end
  #   end
  #
  # @example Add the atom format and parsing method to the default parser
  #   class AtomParsingIncluded < HTTParty::Parser
  #     SupportedFormats.merge!(
  #       {"application/atom+xml" => :atom}
  #     )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 module HTTParty
-  # The default parser used by HTTParty, supports xml, json, html, yaml, and
+  # The default parser used by HTTParty, supports xml, json, html, and
   # plain text.
   #
   # == Custom Parsers
@@ -45,8 +45,6 @@
       'application/javascript' => :json,
       'text/javascript'        => :json,
       'text/html'              => :html,
-      'application/x-yaml'     => :yaml,
-      'text/yaml'              => :yaml,
       'text/plain'             => :plain
     }
 
@@ -120,10 +118,6 @@
       end
     end
 
-    def yaml
-      YAML.load(body)
-    end
-
     def html
       body
     end
```
