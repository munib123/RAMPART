# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 2954_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2954_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 24-65 of the vulnerable file.

    it "cleans double brackets" do
      expect(File.cleanpath('A//B/C')).to eq "A/B/C"
    end

    it "cleans a path with ." do
      expect(File.cleanpath('Hello/./I/.Am/Fred')).to eq "Hello/I/.Am/Fred"
    end

    it "cleans a path with .." do
      expect(File.cleanpath('Hello/../World')).to eq "World"
    end

    it "cleans a path with multiple .." do
      expect(File.cleanpath('A/B/C/../../D')).to eq "A/D"
    end

    it "cleans a path ending in .." do
      expect(File.cleanpath('A/B/C/D/..')).to eq "A/B/C"
    end

    it "passes the initial directory" do
      expect(File.cleanpath('C/../../D')).to eq "../D"
    end

    it "does not remove multiple '../' at the beginning" do
      expect(File.cleanpath('../../A/B')).to eq '../../A/B'
    end
  end

  describe ".open!" do
    it "creates the path before opening" do
      expect(File).to receive(:directory?).with('/path/to').and_return(false)
      expect(FileUtils).to receive(:mkdir_p).with('/path/to')
      expect(File).to receive(:open).with('/path/to/file', 'w')
      File.open!('/path/to/file', 'w')
    end

    it "just opens the file if the path exists" do
      expect(File).to receive(:directory?).with('/path/to').and_return(true)
      expect(FileUtils).not_to receive(:mkdir_p)
      expect(File).to receive(:open).with('/path/to/file', 'w')
      File.open!('/path/to/file', 'w')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,12 +41,12 @@
       expect(File.cleanpath('A/B/C/D/..')).to eq "A/B/C"
     end
 
-    it "passes the initial directory" do
-      expect(File.cleanpath('C/../../D')).to eq "../D"
+    it "does not allow relative path above root" do
+      expect(File.cleanpath('A/../../../../../D')).to eq "D"
     end
 
     it "does not remove multiple '../' at the beginning" do
-      expect(File.cleanpath('../../A/B')).to eq '../../A/B'
+      expect(File.cleanpath('../../A/B')).to eq 'A/B'
     end
   end
 
```
