# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in ruby
**Pair ID:** 1925_4
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1925_4`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```ruby
Lines 6-60 of the vulnerable file.

  let(:file) { File.read(file_path("test.jpg")) }
  let(:filename) { "test.jpg" }
  let(:uri) { "http://www.example.com/#{CGI.escape(filename)}" }

  subject { CarrierWave::Downloader::Base.new(uploader) }

  context "with unicode sybmols in URL" do
    let(:filename) { "юникод.jpg" }
    before do
      stub_request(:get, uri).to_return(body: file)
    end

    let(:remote_file) { subject.download(uri) }

    it "downloads a file" do
      expect(remote_file).to be_an_instance_of(CarrierWave::Downloader::RemoteFile)
    end

    it "sets the filename to the file's decoded sanitized filename" do
      expect(remote_file.original_filename).to eq("#{filename}")
    end
  end

  context "with a URL with internationalized domain name" do
    let(:uri) { "http://ドメイン名例.jp/#{CGI.escape(filename)}" }
    before do
      stub_request(:get, 'http://xn--eckwd4c7cu47r2wf.jp/test.jpg').to_return(body: file)
    end

    it "converts to Punycode URI" do
      expect(subject.process_uri(uri).to_s).to eq 'http://xn--eckwd4c7cu47r2wf.jp/test.jpg'
    end

    it "downloads a file" do
      expect(subject.download(uri).file.read).to eq file
    end
  end

  context "with equal and colons in the query path" do
    let(:query) { 'test=query&with=equal&before=colon:param' }
    let(:uri) { "https://example.com/#{filename}?#{query}" }
    before do
      stub_request(:get, uri).to_return(body: file)
    end

    it "leaves colon in resulting URI" do
      expect(subject.process_uri(uri).query).to eq query
    end

    it "downloads a file" do
      expect(subject.download(uri).file.read).to eq file
    end
  end

  context 'with request headers' do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,21 +23,6 @@
 
     it "sets the filename to the file's decoded sanitized filename" do
       expect(remote_file.original_filename).to eq("#{filename}")
-    end
-  end
-
-  context "with a URL with internationalized domain name" do
-    let(:uri) { "http://ドメイン名例.jp/#{CGI.escape(filename)}" }
-    before do
-      stub_request(:get, 'http://xn--eckwd4c7cu47r2wf.jp/test.jpg').to_return(body: file)
-    end
-
-    it "converts to Punycode URI" do
-      expect(subject.process_uri(uri).to_s).to eq 'http://xn--eckwd4c7cu47r2wf.jp/test.jpg'
-    end
-
-    it "downloads a file" do
-      expect(subject.download(uri).file.read).to eq file
     end
   end
 
@@ -77,10 +62,6 @@
     end
   end
 
-  it "raises an error when trying to download a local file" do
-    expect { subject.download('/etc/passwd') }.to raise_error(CarrierWave::DownloadError)
-  end
-
   context "with missing file" do
     before do
       stub_request(:get, uri).to_return(status: 404)
@@ -95,6 +76,20 @@
     end
   end
 
+  context "with server error" do
+    before do
+      stub_request(:get, uri).to_return(status: 500)
+    end
+
+    it "raises an error when trying to download" do
+      expect{ subject.download(uri) }.to raise_error(CarrierWave::DownloadError)
+    end
+
+    it "doesn't obscure original exception message" do
+      expect { subject.download(uri) }.to raise_error(CarrierWave::DownloadError, /could not download file: 500/)
+    end
+  end
+
   context "with a url that contains space" do
     let(:filename) { "my test.jpg" }
     before do
@@ -111,7 +106,7 @@
     before do
       stub_request(:get, uri).
         to_return(status: 301, body: "Redirecting", headers: { "Location" => another_uri })
-      stub_request(:get, another_uri).to_return(body: file)
+      stub_request(:get, /redirected.jpg/).to_return(body: file)
     end
 
     it "retrieves redirected file" do
@@ -123,7 +118,31 @@
     end
   end
 
+  context "with SSRF prevention" do
+    before do
+      stub_request(:get, 'http://169.254.169.254/').to_return(body: file)
+      stub_request(:get, 'http://127.0.0.1/').to_return(body: file)
+    end
+
+    it "prevents accessing local files" do
+      expect { subject.download('/etc/passwd') }.to raise_error(CarrierWave::DownloadError)
+      expect { subject.download('file:///etc/passwd') }.to raise_error(CarrierWave::DownloadError)
+    end
+
+    it "prevents accessing internal addresses" do
+      expect { uploader.download!("http://169.254.169.254/") }.to raise_error CarrierWave::DownloadError
+      expect { uploader.download!("http://lvh.me/") }.to raise_error CarrierWave::DownloadError
+    end
+  end
+
   describe '#process_uri' do
+    it "converts a URL with internationalized domain name to Punycode URI" do
+      uri = "http://ドメイン名例.jp/#{CGI.escape(filename)}"
+      processed = subject.process_uri(uri)
+      expect(processed.class).to eq(URI::HTTP)
+      expect(processed.to_s).to eq 'http://xn--eckwd4c7cu47r2wf.jp/test.jpg'
+    end
+
     it "parses but not escape already escaped uris" do
       uri = 'http://example.com/%5B.jpg'
       processed = subject.process_uri(uri)
@@ -178,4 +197,16 @@
       expect { subject.process_uri(uri) }.to raise_error(CarrierWave::DownloadError)
     end
   end
+
+  describe "#skip_ssrf_protection?" do
+    let(:uri) { 'http://localhost/test.jpg' }
+    before do
+      WebMock.stub_request(:get, uri).to_return(body: file)
+      allow(subject).to receive(:skip_ssrf_protection?).and_return(true)
+    end
+
+    it "allows local request to be made" do
+      expect(subject.download(uri).read).to eq 'this is stuff'
+    end
+  end
 end
```
