# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 16_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `16_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 407-447 of the vulnerable file.

    gz_io.close
  end

  ##
  # Returns the full path for installing +filename+.
  #
  # If +filename+ is not inside +destination_dir+ an exception is raised.

  def install_location filename, destination_dir # :nodoc:
    raise Gem::Package::PathError.new(filename, destination_dir) if
      filename.start_with? '/'

    destination_dir = File.realpath destination_dir if
      File.respond_to? :realpath
    destination_dir = File.expand_path destination_dir

    destination = File.join destination_dir, filename
    destination = File.expand_path destination

    raise Gem::Package::PathError.new(destination, destination_dir) unless
      destination.start_with? destination_dir

    destination.untaint
    destination
  end

  ##
  # Loads a Gem::Specification from the TarEntry +entry+

  def load_spec entry # :nodoc:
    case entry.full_name
    when 'metadata' then
      @spec = Gem::Specification.from_yaml entry.read
    when 'metadata.gz' then
      args = [entry]
      args << { :external_encoding => Encoding::UTF_8 } if
        Object.const_defined?(:Encoding) &&
          Zlib::GzipReader.method(:wrap).arity != 1

      Zlib::GzipReader.wrap(*args) do |gzio|
        @spec = Gem::Specification.from_yaml gzio.read
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -424,7 +424,7 @@
     destination = File.expand_path destination
 
     raise Gem::Package::PathError.new(destination, destination_dir) unless
-      destination.start_with? destination_dir
+      destination.start_with? destination_dir + '/'
 
     destination.untaint
     destination
```
