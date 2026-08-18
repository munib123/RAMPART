# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 5522_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5522_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 1-29 of the vulnerable file.

module Thin  
  # Raised when a feature is not supported on the
  # current platform.
  class PlatformNotSupported < RuntimeError; end
  
  module VERSION #:nodoc:
    MAJOR    = 1
    MINOR    = 2
    TINY     = 2
    
    STRING   = [MAJOR, MINOR, TINY].join('.')
    
    CODENAME = "I Find Your Lack of Sauce Disturbing".freeze
    
    RACK     = [1, 0].freeze # Rack protocol version
  end
  
  NAME    = 'thin'.freeze
  SERVER  = "#{NAME} #{VERSION::STRING} codename #{VERSION::CODENAME}".freeze  
  
  def self.win?
    RUBY_PLATFORM =~ /mswin|mingw/
  end
  
  def self.linux?
    RUBY_PLATFORM =~ /linux/
  end
  
  def self.ruby_18?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,11 +6,11 @@
   module VERSION #:nodoc:
     MAJOR    = 1
     MINOR    = 2
-    TINY     = 2
+    TINY     = 3
     
     STRING   = [MAJOR, MINOR, TINY].join('.')
     
-    CODENAME = "I Find Your Lack of Sauce Disturbing".freeze
+    CODENAME = "Astroboy".freeze
     
     RACK     = [1, 0].freeze # Rack protocol version
   end
```
