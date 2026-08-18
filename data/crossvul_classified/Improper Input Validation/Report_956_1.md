# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 956_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `956_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 57-97 of the vulnerable file.


      describe ".open" do
        it "makes a copy of the image" do
          image = described_class.open(image_path)
          expect(image.path).not_to eq image_path
          expect(image).to be_valid
          expect(File.extname(image.path)).to eq File.extname(image_path)
        end

        it "accepts a Pathname" do
          image = described_class.open(Pathname(image_path))
          expect(image).to be_valid
        end

        it "loads a remote image" do
          stub_request(:get, "http://example.com/image.jpg")
            .to_return(body: File.read(image_path))
          image = described_class.open("http://example.com/image.jpg")
          expect(image).to be_valid
          expect(File.extname(image.path)).to eq ".jpg"
        end

        it "accepts open-uri options" do
          stub_request(:get, "http://example.com/image.jpg")
            .with(headers: {"Foo" => "Bar"})
            .to_return(body: File.read(image_path))
          described_class.open("http://example.com/image.jpg", {"Foo" => "Bar"})
          described_class.open("http://example.com/image.jpg", ".jpg", {"Foo" => "Bar"})
        end

        it "strips out colons from URL" do
          stub_request(:get, "http://example.com/image.jpg:large")
            .to_return(body: File.read(image_path))
          image = described_class.open("http://example.com/image.jpg:large")
          expect(File.extname(image.path)).to eq ".jpg"
        end

        it "validates the image" do
          expect { described_class.open(image_path(:not)) }
            .to raise_error(MiniMagick::Invalid)
        end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,6 +74,14 @@
           image = described_class.open("http://example.com/image.jpg")
           expect(image).to be_valid
           expect(File.extname(image.path)).to eq ".jpg"
+        end
+
+        it "doesn't allow remote shell execution" do
+          expect {
+            described_class.open("| touch file.txt") # Kernel#open accepts this
+          }.to raise_error(URI::InvalidURIError)
+
+          expect(File.exist?("file.txt")).to eq(false)
         end
 
         it "accepts open-uri options" do
```
