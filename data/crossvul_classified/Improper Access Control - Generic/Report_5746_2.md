# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5746_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5746_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 1-11 of the vulnerable file.

require File.expand_path('../../katello_ssl_tool', __FILE__)

Puppet::Type.type(:privkey).provide(:katello_ssl_tool, :parent => Puppet::Provider::KatelloSslTool::CertFile) do

  protected

  def source_path
    cert_details[:privkey]
  end

end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,4 +8,8 @@
     cert_details[:privkey]
   end
 
+  def mode
+    0400
+  end
+
 end
```
