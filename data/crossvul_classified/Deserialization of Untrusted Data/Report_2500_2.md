# CrossVul Fix Pair: Deserialization of Untrusted Data in ruby
**Pair ID:** 2500_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2500_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```ruby
Lines 328-368 of the vulnerable file.


    Gem.load_yaml

    permissions = 0600 & (~File.umask)
    File.open(credentials_path, 'w', permissions) do |f|
      f.write config.to_yaml
    end

    load_api_keys # reload
  end

  def load_file(filename)
    Gem.load_yaml

    yaml_errors = [ArgumentError]
    yaml_errors << Psych::SyntaxError if defined?(Psych::SyntaxError)

    return {} unless filename and File.exist? filename

    begin
      content = YAML.load(File.read(filename))
      unless content.kind_of? Hash
        warn "Failed to load #{filename} because it doesn't contain valid YAML hash"
        return {}
      end
      return content
    rescue *yaml_errors => e
      warn "Failed to load #{filename}, #{e}"
    rescue Errno::EACCES
      warn "Failed to load #{filename} due to permissions problem."
    end

    {}
  end

  # True if the backtrace option has been specified, or debug is on.
  def backtrace
    @backtrace or $DEBUG
  end

  # The name of the configuration file.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -345,7 +345,7 @@
     return {} unless filename and File.exist? filename
 
     begin
-      content = YAML.load(File.read(filename))
+      content = Gem::SafeYAML.load(File.read(filename))
       unless content.kind_of? Hash
         warn "Failed to load #{filename} because it doesn't contain valid YAML hash"
         return {}
```
