# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 3642_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3642_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 57-79 of the vulnerable file.

      delivery_two = File.join(Mail.delivery_method.settings[:location], 'bob@me.com')
      
      File.read(delivery_one).should eq mail.encoded
      File.read(delivery_two).should eq mail.encoded
    end

    it "should only create files based on the addr_spec of the destination" do
      Mail.defaults do
        delivery_method :file, :location => tmpdir
      end
      
      Mail.deliver do
        from    'roger@moore.com'
        to      '"Long, stupid email address" <mikel@test.lindsaar.net>'
        subject 'invalid RFC2822'
      end
      delivery = File.join(Mail.delivery_method.settings[:location], 'mikel@test.lindsaar.net')
      File.exists?(delivery).should be_true
    end

  end
  
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,6 +74,21 @@
       File.exists?(delivery).should be_true
     end
 
+    it "should use the base name of the file name to prevent file system traversal" do
+      Mail.defaults do
+        delivery_method :file, :location => tmpdir
+      end
+      
+      Mail.deliver do
+        from    'roger@moore.com'
+        to      '../../../../../../../../../../../tmp/pwn'
+        subject 'evil hacker'
+      end
+
+      delivery = File.join(Mail.delivery_method.settings[:location], 'pwn')
+      File.exists?(delivery).should be_true
+    end
+
   end
   
 end
```
