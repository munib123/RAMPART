# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 5552_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5552_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 24-73 of the vulnerable file.

    def initialize(root, headers={}, default_mime = 'text/plain')
      @root = root
      @headers = headers
      @default_mime = default_mime
    end

    def call(env)
      dup._call(env)
    end

    F = ::File

    def _call(env)
      unless ALLOWED_VERBS.include? env["REQUEST_METHOD"]
        return fail(405, "Method Not Allowed")
      end

      path_info = Utils.unescape(env["PATH_INFO"])
      parts = path_info.split SEPS

      parts.inject(0) do |depth, part|
        case part
        when '', '.'
          depth
        when '..'
          return fail(404, "Not Found") if depth - 1 < 0
          depth - 1
        else
          depth + 1
        end
      end

      @path = F.join(@root, *parts)

      available = begin
        F.file?(@path) && F.readable?(@path)
      rescue SystemCallError
        false
      end

      if available
        serving(env)
      else
        fail(404, "File not found: #{path_info}")
      end
    end

    def serving(env)
      last_modified = F.mtime(@path).httpdate
      return [304, {}, []] if env['HTTP_IF_MODIFIED_SINCE'] == last_modified
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,19 +41,14 @@
       path_info = Utils.unescape(env["PATH_INFO"])
       parts = path_info.split SEPS
 
-      parts.inject(0) do |depth, part|
-        case part
-        when '', '.'
-          depth
-        when '..'
-          return fail(404, "Not Found") if depth - 1 < 0
-          depth - 1
-        else
-          depth + 1
-        end
+      clean = []
+
+      parts.each do |part|
+        next if part.empty? || part == '.'
+        part == '..' ? clean.pop : clean << part
       end
 
-      @path = F.join(@root, *parts)
+      @path = F.join(@root, *clean)
 
       available = begin
         F.file?(@path) && F.readable?(@path)
```
