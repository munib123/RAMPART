# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 4400_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4400_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 1-25 of the vulnerable file.

require 'redcarpet.so'
require 'redcarpet/compat'

module Redcarpet
  VERSION = '3.5.0'

  class Markdown
    attr_reader :renderer
  end

  module Render

    # XHTML Renderer
    class XHTML < HTML
      def initialize(extensions = {})
        super(extensions.merge(xhtml: true))
      end
    end

    # HTML + SmartyPants renderer
    class SmartyHTML < HTML
      include SmartyPants
    end

    # A renderer object you can use to deal with users' input. It
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 require 'redcarpet/compat'
 
 module Redcarpet
-  VERSION = '3.5.0'
+  VERSION = '3.5.1'
 
   class Markdown
     attr_reader :renderer
```
