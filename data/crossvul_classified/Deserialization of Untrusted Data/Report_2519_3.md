# CrossVul Fix Pair: Deserialization of Untrusted Data in ruby
**Pair ID:** 2519_3
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2519_3`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```ruby
Lines 29-70 of the vulnerable file.


      def incrby(key, increment)
        namespace(key) { |k| super(k, increment) }
      end

      def decrby(key, increment)
        namespace(key) { |k| super(k, increment) }
      end

      def keys(pattern = "*")
        namespace(pattern) { |p| super(p).map{|key| strip_namespace(key) } }
      end

      def del(*keys)
        super(*keys.map {|key| interpolate(key) }) if keys.any?
      end

      def mget(*keys)
        options = (keys.pop if keys.last.is_a? Hash) || {}
        if keys.any?
          # Marshalling gets extended before Namespace does, so we need to pass options further
          if singleton_class.ancestors.include? Marshalling
            super(*keys.map {|key| interpolate(key) }, options)
          else
            super(*keys.map {|key| interpolate(key) })
          end
        end
      end

      def expire(key, ttl)
         namespace(key) { |k| super(k, ttl) }
      end

      def to_s
        if namespace_str
          "#{super} with namespace #{namespace_str}"
        else
          super
        end
      end

      def flushdb
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,8 +46,8 @@
       def mget(*keys)
         options = (keys.pop if keys.last.is_a? Hash) || {}
         if keys.any?
-          # Marshalling gets extended before Namespace does, so we need to pass options further
-          if singleton_class.ancestors.include? Marshalling
+          # Serialization gets extended before Namespace does, so we need to pass options further
+          if singleton_class.ancestors.include? Serialization
             super(*keys.map {|key| interpolate(key) }, options)
           else
             super(*keys.map {|key| interpolate(key) })
```
