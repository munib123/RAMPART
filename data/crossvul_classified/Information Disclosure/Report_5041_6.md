# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5041_6
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5041_6`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

module Rack
  class MiniProfiler
    class AbstractStore

      def save(page_struct)
        raise NotImplementedError.new("save is not implemented")
      end

      def load(id)
        raise NotImplementedError.new("load is not implemented")
      end

      def set_unviewed(user, id)
        raise NotImplementedError.new("set_unviewed is not implemented")
      end

      def set_viewed(user, id)
        raise NotImplementedError.new("set_viewed is not implemented")
      end

      def set_all_unviewed(user, ids)
        raise NotImplementedError.new("set_all_unviewed is not implemented")
      end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,9 @@
 module Rack
   class MiniProfiler
     class AbstractStore
+
+      # maximum age of allowed tokens before cycling in seconds
+      MAX_TOKEN_AGE = 1800
 
       def save(page_struct)
         raise NotImplementedError.new("save is not implemented")
@@ -31,6 +34,11 @@
         ""
       end
 
+      # a list of tokens that are permitted to access profiler in whitelist mode
+      def allowed_tokens
+        raise NotImplementedError.new("allowed_tokens is not implemented")
+      end
+
     end
   end
 end
```
