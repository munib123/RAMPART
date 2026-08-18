# CrossVul Fix Pair: Deserialization of Untrusted Data in ruby
**Pair ID:** 2500_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2500_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```ruby
Lines 658-698 of the vulnerable file.


    index
  end

  @yaml_loaded = false

  ##
  # Loads YAML, preferring Psych

  def self.load_yaml
    return if @yaml_loaded
    return unless defined?(gem)

    test_syck = ENV['TEST_SYCK']

    # Only Ruby 1.8 and 1.9 have syck
    test_syck = false unless /^1\./ =~ RUBY_VERSION

    unless test_syck
      begin
        gem 'psych', '>= 1.2.1'
      rescue Gem::LoadError
        # It's OK if the user does not have the psych gem installed.  We will
        # attempt to require the stdlib version
      end

      begin
        # Try requiring the gem version *or* stdlib version of psych.
        require 'psych'
      rescue ::LoadError
        # If we can't load psych, thats fine, go on.
      else
        # If 'yaml' has already been required, then we have to
        # be sure to switch it over to the newly loaded psych.
        if defined?(YAML::ENGINE) && YAML::ENGINE.yamler != "psych"
          YAML::ENGINE.yamler = "psych"
        end

        require 'rubygems/psych_additions'
        require 'rubygems/psych_tree'
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -675,7 +675,7 @@
 
     unless test_syck
       begin
-        gem 'psych', '>= 1.2.1'
+        gem 'psych', '>= 2.0.0'
       rescue Gem::LoadError
         # It's OK if the user does not have the psych gem installed.  We will
         # attempt to require the stdlib version
@@ -699,6 +699,7 @@
     end
 
     require 'yaml'
+    require 'rubygems/safe_yaml'
 
     # If we're supposed to be using syck, then we may have to force
     # activate it via the YAML::ENGINE API.
```
