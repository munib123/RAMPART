# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 3730_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3730_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

require 'puppet'
require 'fileutils'
require 'tempfile'

Puppet::Reports.register_report(:store) do
  desc "Store the yaml report on disk.  Each host sends its report as a YAML dump
    and this just stores the file on disk, in the `reportdir` directory.

    These files collect quickly -- one every half hour -- so it is a good idea
    to perform some maintenance on them if you use this report (it's the only
    default report)."

  def process
    # We don't want any tracking back in the fs.  Unlikely, but there
    # you go.
    client = self.host.gsub("..",".")

    dir = File.join(Puppet[:reportdir], client)

    if ! FileTest.exists?(dir)
      FileUtils.mkdir_p(dir)
      FileUtils.chmod_R(0750, dir)
    end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,8 @@
 require 'puppet'
 require 'fileutils'
 require 'tempfile'
+
+SEPARATOR = [Regexp.escape(File::SEPARATOR.to_s), Regexp.escape(File::ALT_SEPARATOR.to_s)].join
 
 Puppet::Reports.register_report(:store) do
   desc "Store the yaml report on disk.  Each host sends its report as a YAML dump
@@ -13,9 +15,11 @@
   def process
     # We don't want any tracking back in the fs.  Unlikely, but there
     # you go.
-    client = self.host.gsub("..",".")
+    if host =~ Regexp.union(/[#{SEPARATOR}]/, /\A\.\.?\Z/)
+      raise ArgumentError, "Invalid node name #{host.inspect}"
+    end
 
-    dir = File.join(Puppet[:reportdir], client)
+    dir = File.join(Puppet[:reportdir], host)
 
     if ! FileTest.exists?(dir)
       FileUtils.mkdir_p(dir)
@@ -42,17 +46,20 @@
       FileUtils.mv(f.path, file)
     rescue => detail
       puts detail.backtrace if Puppet[:trace]
-      Puppet.warning "Could not write report for #{client} at #{file}: #{detail}"
+      Puppet.warning "Could not write report for #{host} at #{file}: #{detail}"
     end
 
     # Only testing cares about the return value
     file
   end
 
-  # removes all reports for a given host
+  # removes all reports for a given host?
   def self.destroy(host)
-    client = host.gsub("..",".")
-    dir = File.join(Puppet[:reportdir], client)
+    if host =~ Regexp.union(/[#{SEPARATOR}]/, /\A\.\.?\Z/)
+      raise ArgumentError, "Invalid node name #{host.inspect}"
+    end
+
+    dir = File.join(Puppet[:reportdir], host)
 
     if File.exists?(dir)
       Dir.entries(dir).each do |file|
```
