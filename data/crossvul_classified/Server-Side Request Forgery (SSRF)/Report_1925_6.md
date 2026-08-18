# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in ruby
**Pair ID:** 1925_6
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1925_6`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```ruby
Lines 487-527 of the vulnerable file.

          expect(instance.images.map(&:cache_name)).to eq(['1369894322-123-0123-1234/test.jpg'])
        end
      end

      context "when an empty string is assigned" do
        before do
          instance.images = [test_file_stub]
          instance.store_images!
          instance.images_cache = [''].to_json
        end

        it "does not write over a previously stored file" do
          expect(instance.images[0].current_path).to match(/test.jpg$/)
        end
      end
    end

    describe "#remote_images_urls" do
      subject { instance.remote_images_urls }

      before { stub_request(:get, "www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub)) }

      context "returns nil" do
        it { is_expected.to be_nil }
      end

      context "returns previously cached URL" do
        before { instance.remote_images_urls = ["http://www.example.com/test.jpg"] }

        it { is_expected.to eq(["http://www.example.com/test.jpg"]) }
      end
    end

    describe "#remote_images_urls=" do
      subject(:images) { instance.images }

      before do
        stub_request(:get, "www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub))
        stub_request(:get, "http://www.example.com/test.txt").to_return(status: 404)
        instance.remote_images_urls = remote_images_url
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -504,7 +504,7 @@
     describe "#remote_images_urls" do
       subject { instance.remote_images_urls }
 
-      before { stub_request(:get, "www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub)) }
+      before { stub_request(:get, "http://www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub)) }
 
       context "returns nil" do
         it { is_expected.to be_nil }
@@ -521,7 +521,7 @@
       subject(:images) { instance.images }
 
       before do
-        stub_request(:get, "www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub))
+        stub_request(:get, "http://www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub))
         stub_request(:get, "http://www.example.com/test.txt").to_return(status: 404)
         instance.remote_images_urls = remote_images_url
       end
@@ -733,7 +733,7 @@
 
         context "when file was downloaded" do
           before do
-            stub_request(:get, "www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub))
+            stub_request(:get, "http://www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub))
             instance.remote_images_urls = ["http://www.example.com/#{test_file_name}"]
           end
 
@@ -790,7 +790,7 @@
 
         context "when file was downloaded" do
           before do
-            stub_request(:get, "www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub))
+            stub_request(:get, "http://www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub))
             instance.remote_images_urls = ["http://www.example.com/#{test_file_name}"]
           end
 
@@ -803,8 +803,8 @@
       subject(:images_download_errors) { instance.images_download_errors }
 
       before do
-        stub_request(:get, "www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub))
-        stub_request(:get, "www.example.com/missing.jpg").to_return(status: 404)
+        stub_request(:get, "http://www.example.com/#{test_file_name}").to_return(body: File.read(test_file_stub))
+        stub_request(:get, "http://www.example.com/missing.jpg").to_return(status: 404)
       end
 
       describe "default behaviour" do
@@ -978,7 +978,7 @@
 
     context "when a downloaded image fails an integity check" do
       before do
-        stub_request(:get, "www.example.com/#{test_file_name}").to_return(body: test_file_stub)
+        stub_request(:get, "http://www.example.com/#{test_file_name}").to_return(body: test_file_stub)
       end
 
       it { expect(running {instance.remote_images_urls = ["http://www.example.com/#{test_file_name}"]}).to raise_error(CarrierWave::IntegrityError) }
@@ -1010,7 +1010,7 @@
 
     context "when a downloaded image fails an integity check" do
       before do
-        stub_request(:get, "www.example.com/#{test_file_name}").to_return(body: test_file_stub)
+        stub_request(:get, "http://www.example.com/#{test_file_name}").to_return(body: test_file_stub)
       end
 
       it { expect(running {instance.remote_images_urls = ["http://www.example.com/#{test_file_name}"]}).to raise_error(CarrierWave::ProcessingError) }
```
