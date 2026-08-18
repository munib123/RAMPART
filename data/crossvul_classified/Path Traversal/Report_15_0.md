# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 15_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `15_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 361-401 of the vulnerable file.

  # extracted.

  def extract_tar_gz io, destination_dir, pattern = "*" # :nodoc:
    open_tar_gz io do |tar|
      tar.each do |entry|
        next unless File.fnmatch pattern, entry.full_name, File::FNM_DOTMATCH

        destination = install_location entry.full_name, destination_dir

        FileUtils.rm_rf destination

        mkdir_options = {}
        mkdir_options[:mode] = entry.header.mode if entry.directory?
        mkdir =
          if entry.directory? then
            destination
          else
            File.dirname destination
          end

        FileUtils.mkdir_p mkdir, mkdir_options

        File.open destination, 'wb' do |out|
          out.write entry.read
          FileUtils.chmod entry.header.mode, destination
        end if entry.file?

        File.symlink(entry.header.linkname, destination) if entry.symlink?

        verbose destination
      end
    end
  end

  ##
  # Gzips content written to +gz_io+ to +io+.
  #--
  # Also sets the gzip modification time to the package build time to ease
  # testing.

  def gzip_to io # :yields: gz_io
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -378,7 +378,7 @@
             File.dirname destination
           end
 
-        FileUtils.mkdir_p mkdir, mkdir_options
+        mkdir_p_safe mkdir, mkdir_options, destination_dir, entry.full_name
 
         File.open destination, 'wb' do |out|
           out.write entry.read
@@ -416,13 +416,10 @@
     raise Gem::Package::PathError.new(filename, destination_dir) if
       filename.start_with? '/'
 
-    destination_dir = File.realpath destination_dir if
-      File.respond_to? :realpath
+    destination_dir = realpath destination_dir
     destination_dir = File.expand_path destination_dir
 
     destination = File.join destination_dir, filename
-    destination = File.realpath destination if
-      File.respond_to? :realpath
     destination = File.expand_path destination
 
     raise Gem::Package::PathError.new(destination, destination_dir) unless
@@ -430,6 +427,22 @@
 
     destination.untaint
     destination
+  end
+
+  def mkdir_p_safe mkdir, mkdir_options, destination_dir, file_name
+    destination_dir = realpath File.expand_path(destination_dir)
+    parts = mkdir.split(File::SEPARATOR)
+    parts.reduce do |path, basename|
+      path = realpath path  unless path == ""
+      path = File.expand_path(path + File::SEPARATOR + basename)
+      lstat = File.lstat path rescue nil
+      if !lstat || !lstat.directory?
+        unless path.start_with? destination_dir and (FileUtils.mkdir path, mkdir_options rescue false)
+          raise Gem::Package::PathError.new(file_name, destination_dir)
+        end
+      end
+      path
+    end
   end
 
   ##
@@ -622,6 +635,16 @@
     raise Gem::Package::FormatError.new(e.message, entry.full_name)
   end
 
+  if File.respond_to? :realpath
+    def realpath file
+      File.realpath file
+    end
+  else
+    def realpath file
+      file
+    end
+  end
+
 end
 
 require 'rubygems/package/digest_io'
```
