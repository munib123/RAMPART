# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3644_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3644_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 12-52 of the vulnerable file.

    begin
      require 'tlsmail'
    rescue LoadError
      raise "You need to install tlsmail if you are using ruby <= 1.8.6"
    end
  end

  if RUBY_VERSION >= "1.9.0"
    require 'mail/version_specific/ruby_1_9'
    RubyVer = Ruby19
  else
    require 'mail/version_specific/ruby_1_8'
    RubyVer = Ruby18
  end

  require 'mail/version'

  require 'mail/core_extensions/nil'
  require 'mail/core_extensions/object'
  require 'mail/core_extensions/string'
  require 'mail/core_extensions/shellwords' unless String.new.respond_to?(:shellescape)
  require 'mail/core_extensions/smtp' if RUBY_VERSION < '1.9.3'
  require 'mail/indifferent_hash'

  # Only load our multibyte extensions if AS is not already loaded
  if defined?(ActiveSupport)
    require 'active_support/inflector'
  else
    require 'mail/core_extensions/string/access'
    require 'mail/core_extensions/string/multibyte'
    require 'mail/multibyte'
  end

  require 'mail/patterns'
  require 'mail/utilities'
  require 'mail/configuration'

  # Autoload mail send and receive classes.
  require 'mail/network'

  require 'mail/message'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,7 @@
   require 'mail/core_extensions/nil'
   require 'mail/core_extensions/object'
   require 'mail/core_extensions/string'
-  require 'mail/core_extensions/shellwords' unless String.new.respond_to?(:shellescape)
+  require 'mail/core_extensions/shell_escape'
   require 'mail/core_extensions/smtp' if RUBY_VERSION < '1.9.3'
   require 'mail/indifferent_hash'
 
```
