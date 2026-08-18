# CrossVul Fix Pair: Deserialization of Untrusted Data in ruby
**Pair ID:** 2500_6
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2500_6`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```ruby
Lines 1084-1124 of the vulnerable file.

          return trail.reverse if to_spec.contains_requirable_file? path
        end
      end
    end

    []
  end

  ##
  # Special loader for YAML files.  When a Specification object is loaded
  # from a YAML file, it bypasses the normal Ruby object initialization
  # routine (#initialize).  This method makes up for that and deals with
  # gems of different ages.
  #
  # +input+ can be anything that YAML.load() accepts: String or IO.

  def self.from_yaml(input)
    Gem.load_yaml

    input = normalize_yaml_input input
    spec = YAML.load input

    if spec && spec.class == FalseClass then
      raise Gem::EndOfYAMLException
    end

    unless Gem::Specification === spec then
      raise Gem::Exception, "YAML data doesn't evaluate to gem specification"
    end

    spec.specification_version ||= NONEXISTENT_SPECIFICATION_VERSION
    spec.reset_nil_attributes_to_default

    spec
  end

  ##
  # Return the latest specs, optionally including prerelease specs if
  # +prerelease+ is true.

  def self.latest_specs prerelease = false
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1101,7 +1101,7 @@
     Gem.load_yaml
 
     input = normalize_yaml_input input
-    spec = YAML.load input
+    spec = Gem::SafeYAML.safe_load input
 
     if spec && spec.class == FalseClass then
       raise Gem::EndOfYAMLException
```
