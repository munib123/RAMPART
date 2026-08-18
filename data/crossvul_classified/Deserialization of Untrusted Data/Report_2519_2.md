# CrossVul Fix Pair: Deserialization of Untrusted Data in ruby
**Pair ID:** 2519_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2519_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```ruby
Lines 33-73 of the vulnerable file.

          extract_host_options_from_hash(uri)
        else
          extract_host_options_from_uri(uri)
        end
      end

      def self.extract_host_options_from_hash(options)
        options = normalize_key_names(options)
        if host_options?(options)
          options
        else
          nil 
        end
      end

      def self.normalize_key_names(options)
        options = options.dup
        if options.key?(:key_prefix) && !options.key?(:namespace)
          options[:namespace] = options.delete(:key_prefix) # RailsSessionStore
        end
        options[:raw] = !options[:marshalling]
        options
      end

      def self.host_options?(options)
        if options.keys.any? {|n| [:host, :db, :port].include?(n) }
          options
        else
          nil # just to be clear
        end
      end

      def self.extract_host_options_from_uri(uri)
        uri = URI.parse(uri)
        _, db, namespace = if uri.path
                             uri.path.split(/\//)
                           end

        options = {
          :host     => uri.hostname,
          :port     => uri.port || DEFAULT_PORT, 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,7 +50,14 @@
         if options.key?(:key_prefix) && !options.key?(:namespace)
           options[:namespace] = options.delete(:key_prefix) # RailsSessionStore
         end
-        options[:raw] = !options[:marshalling]
+        options[:raw] = case
+                        when options.key?(:serializer)
+                          options[:serializer].nil?
+                        when options.key?(:marshalling)
+                          !options[:marshalling]
+                        else
+                          false
+                        end
         options
       end
 
```
