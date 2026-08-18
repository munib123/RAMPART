# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in ruby
**Pair ID:** 1926_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1926_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```ruby
Lines 48-88 of the vulnerable file.

      __deprecated__ :store
      @store.instance_variable_get(:@jar)
    end

    # See HTTP::CookieJar#load.
    def load_cookiestxt(io)
      __deprecated__ :load
      load(io, :cookiestxt)
    end

    # See HTTP::CookieJar#save.
    def dump_cookiestxt(io)
      __deprecated__ :save
      save(io, :cookiestxt)
    end
  end

  class CookieJar < ::HTTP::CookieJar
    def save(output, *options)
      output.respond_to?(:write) or
        return open(output, 'w') { |io| save(io, *options) }

      opthash = {
        :format => :yaml,
        :session => false,
      }
      case options.size
      when 0
      when 1
        case options = options.first
        when Symbol
          opthash[:format] = options
        else
          opthash.update(options) if options
        end
      when 2
        opthash[:format], options = options
        opthash.update(options) if options
      else
        raise ArgumentError, 'wrong number of arguments (%d for 1-3)' % (1 + options.size)
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,7 +65,7 @@
   class CookieJar < ::HTTP::CookieJar
     def save(output, *options)
       output.respond_to?(:write) or
-        return open(output, 'w') { |io| save(io, *options) }
+        return ::File.open(output, 'w') { |io| save(io, *options) }
 
       opthash = {
         :format => :yaml,
@@ -119,7 +119,7 @@
 
     def load(input, *options)
       input.respond_to?(:write) or
-        return open(input, 'r') { |io| load(io, *options) }
+        return ::File.open(input, 'r') { |io| load(io, *options) }
 
       opthash = {
         :format => :yaml,
```
