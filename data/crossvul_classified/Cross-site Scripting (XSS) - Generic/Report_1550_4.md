# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 1550_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1550_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 26-46 of the vulnerable file.

    assert ! Paperclip::MediaTypeSpoofDetector.using(file, "data").spoofed?
  end

  it 'does not reject when the supplied file is an IOAdapter' do
    adapter = Paperclip.io_adapters.for(File.new(fixture_file("5k.png")))
    assert ! Paperclip::MediaTypeSpoofDetector.using(adapter, adapter.original_filename).spoofed?
  end

  it 'does not reject when the extension => content_type is in :content_type_mappings' do
    begin
      Paperclip.options[:content_type_mappings] = { pem: "text/plain" }
      file = Tempfile.open(["test", ".PEM"])
      file.puts "Certificate!"
      file.close
      adapter = Paperclip.io_adapters.for(File.new(file.path));
      assert ! Paperclip::MediaTypeSpoofDetector.using(adapter, adapter.original_filename).spoofed?
    ensure
      Paperclip.options[:content_type_mappings] = {}
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,4 +43,14 @@
       Paperclip.options[:content_type_mappings] = {}
     end
   end
+
+  it "rejects a file if named .html and is as HTML, but we're told JPG" do
+    file = File.open(fixture_file("empty.html"))
+    assert Paperclip::MediaTypeSpoofDetector.using(file, "empty.html", "image/jpg").spoofed?
+  end
+
+  it "does not reject is content_type is empty but otherwise checks out" do
+    file = File.open(fixture_file("empty.html"))
+    assert ! Paperclip::MediaTypeSpoofDetector.using(file, "empty.html", "").spoofed?
+  end
 end
```
