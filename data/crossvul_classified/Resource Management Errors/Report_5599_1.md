# CrossVul Fix Pair: Resource Management Errors in ruby
**Pair ID:** 5599_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5599_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```ruby
Lines 71-112 of the vulnerable file.

        if parent_sought != parent.downcase
          raise XRDSFraud.new(sprintf("%s can not come from %s", parent_sought,
                                      parent))
        end

        childID = parent_sought
      }

      root = XRI.root_authority(iname)
      if not XRI.provider_is_authoritative(root, childID)
        raise XRDSFraud.new(sprintf("%s can not come from root %s", childID, root))
      end

      return canonicalID
    end

    class XRDSError < StandardError
    end

    def Yadis::parseXRDS(text)
      if text.nil?
        raise XRDSError.new("Not an XRDS document.")
      end

      begin
        d = REXML::Document.new(text)
      rescue RuntimeError => why
        raise XRDSError.new("Not an XRDS document. Failed to parse XML.")
      end

      if is_xrds?(d)
        return d
      else
        raise XRDSError.new("Not an XRDS document.")
      end
    end

    def Yadis::is_xrds?(xrds_tree)
      xrds_root = xrds_tree.root
      return (!xrds_root.nil? and
        xrds_root.name == 'XRDS' and
        xrds_root.namespace == XRDS_NS)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,21 +88,31 @@
     end
 
     def Yadis::parseXRDS(text)
-      if text.nil?
-        raise XRDSError.new("Not an XRDS document.")
+      disable_entity_expansion do
+        if text.nil?
+          raise XRDSError.new("Not an XRDS document.")
+        end
+
+        begin
+          d = REXML::Document.new(text)
+        rescue RuntimeError => why
+          raise XRDSError.new("Not an XRDS document. Failed to parse XML.")
+        end
+
+        if is_xrds?(d)
+          return d
+        else
+          raise XRDSError.new("Not an XRDS document.")
+        end
       end
+    end
 
-      begin
-        d = REXML::Document.new(text)
-      rescue RuntimeError => why
-        raise XRDSError.new("Not an XRDS document. Failed to parse XML.")
-      end
-
-      if is_xrds?(d)
-        return d
-      else
-        raise XRDSError.new("Not an XRDS document.")
-      end
+    def Yadis::disable_entity_expansion
+      _previous_ = REXML::Document::entity_expansion_limit
+      REXML::Document::entity_expansion_limit = 0
+      yield
+    ensure
+      REXML::Document::entity_expansion_limit = _previous_
     end
 
     def Yadis::is_xrds?(xrds_tree)
```
