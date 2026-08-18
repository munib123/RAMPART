# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3487_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3487_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 125-166 of the vulnerable file.


      template_paths = Dir[query].reject { |filename|
        File.directory?(filename) ||
          !sanitizer[File.dirname(filename)].include?(filename)
      }

      template_paths.map { |template|
        handler, format = extract_handler_and_format(template, formats)
        contents = File.binread template

        Template.new(contents, File.expand_path(template), handler,
          :virtual_path => path.virtual,
          :format       => format,
          :updated_at   => mtime(template))
      }
    end

    # Helper for building query glob string based on resolver's pattern.
    def build_query(path, details)
      query = @pattern.dup
      query.gsub!(/\:prefix(\/)?/, path.prefix.empty? ? "" : "#{path.prefix}\\1") # prefix can be empty...
      query.gsub!(/\:action/, path.partial? ? "_#{path.name}" : path.name)

      details.each do |ext, variants|
        query.gsub!(/\:#{ext}/, "{#{variants.compact.uniq.join(',')}}")
      end

      File.expand_path(query, @path)
    end

    # Returns the file mtime from the filesystem.
    def mtime(p)
      File.mtime(p)
    end

    # Extract handler and formats from path. If a format cannot be a found neither
    # from the path, or the handler, we should return the array of formats given
    # to the resolver.
    def extract_handler_and_format(path, default_formats)
      pieces = File.basename(path).split(".")
      pieces.shift
      handler = Template.handler_for_extension(pieces.pop)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,14 +142,22 @@
     # Helper for building query glob string based on resolver's pattern.
     def build_query(path, details)
       query = @pattern.dup
-      query.gsub!(/\:prefix(\/)?/, path.prefix.empty? ? "" : "#{path.prefix}\\1") # prefix can be empty...
-      query.gsub!(/\:action/, path.partial? ? "_#{path.name}" : path.name)
+
+      prefix = path.prefix.empty? ? "" : "#{escape_entry(path.prefix)}\\1"
+      query.gsub!(/\:prefix(\/)?/, prefix)
+
+      partial = escape_entry(path.partial? ? "_#{path.name}" : path.name)
+      query.gsub!(/\:action/, partial)
 
       details.each do |ext, variants|
         query.gsub!(/\:#{ext}/, "{#{variants.compact.uniq.join(',')}}")
       end
 
       File.expand_path(query, @path)
+    end
+
+    def escape_entry(entry)
+      entry.gsub(/(\*|\[|\]|\{|\}|\?)/, "\\\\\\1")
     end
 
     # Returns the file mtime from the filesystem.
@@ -228,8 +236,9 @@
   class OptimizedFileSystemResolver < FileSystemResolver #:nodoc:
     def build_query(path, details)
       exts = EXTENSIONS.map { |ext| details[ext] }
-
-      File.join(@path, path) + exts.map { |ext|
+      query = escape_entry(File.join(@path, path))
+
+      query + exts.map { |ext|
         "{#{ext.compact.uniq.map { |e| ".#{e}," }.join}}"
       }.join
     end
```
