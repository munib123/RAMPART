# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 2954_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2954_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 23-63 of the vulnerable file.

      break if from[0] != to[0]
      from.shift; to.shift
    end
    from.pop
    join(*(from.map { RELATIVE_PARENTDIR } + to))
  end

  # Cleans a path by removing extraneous '..', '.' and '/' characters
  #
  # @example Clean a path
  #   File.cleanpath('a/b//./c/../e') # => "a/b/e"
  # @param [String] path the path to clean
  # @return [String] the sanitized path
  def self.cleanpath(path)
    path = path.split(SEPARATOR)
    path = path.inject([]) do |acc, comp|
      next acc if comp == RELATIVE_SAMEDIR
      if comp == RELATIVE_PARENTDIR && !acc.empty? && acc.last != RELATIVE_PARENTDIR
        acc.pop
        next acc
      end
      acc << comp
    end
    File.join(*path)
  end

  # @group Reading Files

  # Forces opening a file (for writing) by first creating the file's directory
  # @param [String] file the filename to open
  # @since 0.5.2
  def self.open!(file, *args, &block)
    dir = dirname(file)
    FileUtils.mkdir_p(dir) unless directory?(dir)
    open(file, *args, &block)
  end

  # Reads a file with binary encoding
  # @return [String] the ascii-8bit encoded data
  # @since 0.5.3
  def self.read_binary(file)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,8 @@
       if comp == RELATIVE_PARENTDIR && !acc.empty? && acc.last != RELATIVE_PARENTDIR
         acc.pop
         next acc
+      elsif comp == RELATIVE_PARENTDIR && acc.empty?
+        next acc
       end
       acc << comp
     end
```
