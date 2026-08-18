# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in ruby
**Pair ID:** 1925_5
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1925_5`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

require 'spec_helper'

describe CarrierWave::Downloader::RemoteFile do
  let(:file) do
    File.open(file_path("test.jpg")).tap { |f| OpenURI::Meta.init(f) }
  end
  subject { CarrierWave::Downloader::RemoteFile.new(file) }

  before do
    subject.base_uri = URI.parse 'http://example.com/test'
    subject.meta_add_field 'content-type', 'image/jpeg'
  end

  it 'sets file extension based on content-type if missing' do
    expect(subject.original_filename).to eq "test.jpeg"
  end

  describe 'with content-disposition' do
    before do
      subject.meta_add_field 'content-disposition', content_disposition
    end

    context 'when filename is quoted' do
      let(:content_disposition){ 'filename="another_test.jpg"' }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,23 +1,61 @@
 require 'spec_helper'
 
 describe CarrierWave::Downloader::RemoteFile do
+  subject { CarrierWave::Downloader::RemoteFile.new(file) }
   let(:file) do
-    File.open(file_path("test.jpg")).tap { |f| OpenURI::Meta.init(f) }
-  end
-  subject { CarrierWave::Downloader::RemoteFile.new(file) }
-
-  before do
-    subject.base_uri = URI.parse 'http://example.com/test'
-    subject.meta_add_field 'content-type', 'image/jpeg'
+    Net::HTTPSuccess.new('1.0', '200', "").tap do |response|
+      response.body = File.read(file_path("test.jpg"))
+      response.instance_variable_set(:@read, true)
+      response.uri = URI.parse 'http://example.com/test'
+      response['content-type'] = 'image/jpeg'
+      response['vary'] = 'Accept-Encoding'
+    end
   end
 
-  it 'sets file extension based on content-type if missing' do
-    expect(subject.original_filename).to eq "test.jpeg"
+  context 'with Net::HTTPResponse instance' do
+    it 'returns content type' do
+      expect(subject.content_type).to eq 'image/jpeg'
+    end
+
+    it 'returns header' do
+      expect(subject.headers['vary']).to eq 'Accept-Encoding'
+    end
+
+    it 'returns URI' do
+      expect(subject.uri.to_s).to eq 'http://example.com/test'
+    end
   end
 
-  describe 'with content-disposition' do
+  context 'with OpenURI::Meta instance' do
+    let(:file) do
+      File.open(file_path("test.jpg")).tap { |f| OpenURI::Meta.init(f) }.tap do |file|
+        file.base_uri = URI.parse 'http://example.com/test'
+        file.meta_add_field 'content-type', 'image/jpeg'
+        file.meta_add_field 'vary', 'Accept-Encoding'
+      end
+    end
+    it 'returns content type' do
+      expect(subject.content_type).to eq 'image/jpeg'
+    end
+
+    it 'returns header' do
+      expect(subject.headers['vary']).to eq 'Accept-Encoding'
+    end
+
+    it 'returns URI' do
+      expect(subject.uri.to_s).to eq 'http://example.com/test'
+    end
+  end
+
+
+  describe '#original_filename' do
+    let(:content_disposition){ nil }
     before do
-      subject.meta_add_field 'content-disposition', content_disposition
+      file['content-disposition'] = content_disposition if content_disposition
+    end
+
+    it 'sets file extension based on content-type if missing' do
+      expect(subject.original_filename).to eq "test.jpeg"
     end
 
     context 'when filename is quoted' do
```
