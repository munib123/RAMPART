# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 3730_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3730_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 27-48 of the vulnerable file.

      Time.stubs(:now).returns(Time.parse("2011-01-06 12:00:00 UTC"))
      @report.process

      File.read(File.join(Puppet[:reportdir], @report.host, "201101061200.yaml")).should == @report.to_yaml
    end

    it "should write to the report directory in the correct sequence" do
      # By doing things in this sequence we should protect against race
      # conditions
      Time.stubs(:now).returns(Time.parse("2011-01-06 12:00:00 UTC"))
      writeseq = sequence("write")
      file = mock "file"
      Tempfile.expects(:new).in_sequence(writeseq).returns(file)
      file.expects(:chmod).in_sequence(writeseq).with(0640)
      file.expects(:print).with(@report.to_yaml).in_sequence(writeseq)
      file.expects(:close).in_sequence(writeseq)
      file.stubs(:path).returns(File.join(Dir.tmpdir, "foo123"))
      FileUtils.expects(:mv).in_sequence(writeseq).with(File.join(Dir.tmpdir, "foo123"), File.join(Puppet[:reportdir], @report.host, "201101061200.yaml"))
      @report.process
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,5 +44,33 @@
       FileUtils.expects(:mv).in_sequence(writeseq).with(File.join(Dir.tmpdir, "foo123"), File.join(Puppet[:reportdir], @report.host, "201101061200.yaml"))
       @report.process
     end
+
+    ['..', 'hello/', '/hello', 'he/llo', 'hello/..', '.'].each do |node|
+      it "rejects #{node.inspect}" do
+        @report.host = node
+        expect { @report.process }.to raise_error(ArgumentError, /Invalid node/)
+      end
+    end
+
+    ['.hello', 'hello.', '..hi', 'hi..'].each do |node|
+      it "accepts #{node.inspect}" do
+        @report.host = node
+        @report.process
+      end
+    end
+  end
+
+  describe "::destroy" do
+    ['..', 'hello/', '/hello', 'he/llo', 'hello/..', '.'].each do |node|
+      it "rejects #{node.inspect}" do
+        expect { processor.destroy(node) }.to raise_error(ArgumentError, /Invalid node/)
+      end
+    end
+
+    ['.hello', 'hello.', '..hi', 'hi..'].each do |node|
+      it "accepts #{node.inspect}" do
+        processor.destroy(node)
+      end
+    end
   end
 end
```
