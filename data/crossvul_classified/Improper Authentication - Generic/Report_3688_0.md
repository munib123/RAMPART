# CrossVul Fix Pair: Improper Authentication in ruby
**Pair ID:** 3688_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3688_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```ruby
Lines 133-173 of the vulnerable file.

      def deny?
        type == :deny
      end

      def exact?
        @exact == :exact
      end

      def initialize(type, pattern)
        self.type = type
        self.pattern = pattern
      end

      # Are we an IP type?
      def ip?
        name == :ip
      end

      # Does this declaration match the name/ip combo?
      def match?(name, ip)
        ip? ? pattern.include?(IPAddr.new(ip)) : matchname?(name)
      end

      # Set the pattern appropriately.  Also sets the name and length.
      def pattern=(pattern)
        parse(pattern)
        @orig = pattern
      end

      # Mapping a type of statement into a return value.
      def result
        type == :allow
      end

      def to_s
        "#{type}: #{pattern}"
      end

      # Set the declaration type.  Either :allow or :deny.
      def type=(type)
        type = symbolize(type)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,7 +150,16 @@
 
       # Does this declaration match the name/ip combo?
       def match?(name, ip)
-        ip? ? pattern.include?(IPAddr.new(ip)) : matchname?(name)
+        if ip?
+          if pattern.include?(IPAddr.new(ip))
+            Puppet.deprecation_warning "Authentication based on IP address is deprecated; please use certname-based rules instead"
+            true
+          else
+            false
+          end
+        else
+          matchname?(name)
+        end
       end
 
       # Set the pattern appropriately.  Also sets the name and length.
@@ -212,7 +221,6 @@
 
       # Convert the name to a common pattern.
       def munge_name(name)
-        # LAK:NOTE http://snurl.com/21zf8  [groups_google_com]
         # Change to name.downcase.split(".",-1).reverse for FQDN support
         name.downcase.split(".").reverse
       end
```
