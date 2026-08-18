# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 3729_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3729_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 10-31 of the vulnerable file.

describe processor do
  describe "#process" do
    include PuppetSpec::Files
    before :each do
      Puppet[:reportdir] = tmpdir('reports') << '/reports' 
      @report = YAML.load_file(File.join(PuppetSpec::FIXTURE_DIR, 'yaml/report2.6.x.yaml')).extend processor
    end

    it "should create a report directory for the client if one doesn't exist" do
      @report.process

      File.should be_directory(File.join(Puppet[:reportdir], @report.host))
    end

    it "should write the report to the file in YAML" do
      Time.stubs(:now).returns(Time.parse("2011-01-06 12:00:00 UTC"))
      @report.process

      File.read(File.join(Puppet[:reportdir], @report.host, "201101061200.yaml")).should == @report.to_yaml
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,5 +27,19 @@
 
       File.read(File.join(Puppet[:reportdir], @report.host, "201101061200.yaml")).should == @report.to_yaml
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
   end
 end
```
