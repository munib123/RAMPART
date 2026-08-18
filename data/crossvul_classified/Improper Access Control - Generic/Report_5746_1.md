# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5746_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5746_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 158-198 of the vulnerable file.

    end

    def self.build_path(file_name = nil)
      File.join("/root/ssl-build", file_name)
    end

  end

  class CertFile < Puppet::Provider

    include Puppet::Util::Checksums

    initvars

    def exists?
      return false unless File.exists?(resource[:path])
      checksum(expected_content) == checksum(current_content)
    end

    def create
      File.open(resource[:path], "w") { |f| f << expected_content }
    end

    protected

    def expected_content
      File.read(source_path)
    end

    def current_content
      File.read(resource[:path])
    end


    def checksum(content)
      md5(content)
    end

    # what path to copy from
    def source_path
      raise NotImplementedError
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -175,7 +175,7 @@
     end
 
     def create
-      File.open(resource[:path], "w") { |f| f << expected_content }
+      File.open(resource[:path], "w", mode) { |f| f << expected_content }
     end
 
     protected
@@ -196,6 +196,10 @@
     # what path to copy from
     def source_path
       raise NotImplementedError
+    end
+
+    def mode
+      0644
     end
 
     def cert_details
```
