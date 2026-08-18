# CrossVul Fix Pair: Deserialization of Untrusted Data in ruby
**Pair ID:** 2500_4
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2500_4`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```ruby
Lines 84-124 of the vulnerable file.

          out.write file_data
        end

        verbose destination
      end
    end
  rescue Zlib::DataError
    raise Gem::Exception, errstr
  end

  ##
  # Reads the file list section from the old-format gem +io+

  def file_list io # :nodoc:
    header = String.new

    read_until_dashes io do |line|
      header << line
    end

    YAML.load header
  end

  ##
  # Reads lines until a "---" separator is found

  def read_until_dashes io # :nodoc:
    while (line = io.gets) && line.chomp.strip != "---" do
      yield line if block_given?
    end
  end

  ##
  # Skips the Ruby self-install header in +io+.

  def skip_ruby io # :nodoc:
    loop do
      line = io.gets

      return if line.chomp == '__END__'
      break unless line
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,7 +101,7 @@
       header << line
     end
 
-    YAML.load header
+    Gem::SafeYAML.safe_load header
   end
 
   ##
```
