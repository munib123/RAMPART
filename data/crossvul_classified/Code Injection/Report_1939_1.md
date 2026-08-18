# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 1939_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1939_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 191-231 of the vulnerable file.

    it 'supports passing write options to RMagick' do
      allow(::Magick::Image).to receive_messages(:read => image)
      expect_any_instance_of(::Magick::Image::Info).to receive(:quality=).with(50)
      expect_any_instance_of(::Magick::Image::Info).to receive(:depth=).with(8)

      instance.manipulate! do |image, index, options|
        options[:write] = {
          :quality => 50,
          :depth => 8
        }
        image
      end
    end

    it 'supports passing read options to RMagick' do
      expect_any_instance_of(::Magick::Image::Info).to receive(:density=).with(10)
      expect_any_instance_of(::Magick::Image::Info).to receive(:size=).with("200x200")

      instance.manipulate! :read => {
          :density => 10,
          :size => %{"200x200"}
        }
    end
  end

  describe "#width and #height" do
    it "returns the width and height of the image" do
      instance.resize_to_fill(200, 300)
      expect(instance.width).to eq(200)
      expect(instance.height).to eq(300)
    end
  end

  describe '#dimension_from' do
    it 'evaluates procs' do
      instance.resize_to_fill(Proc.new { 200 }, Proc.new { 200 })

      expect(instance).to have_dimensions(200, 200)
    end

    it 'evaluates procs with uploader instance' do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -208,8 +208,40 @@
 
       instance.manipulate! :read => {
           :density => 10,
-          :size => %{"200x200"}
+          :size => "200x200"
         }
+    end
+
+    it 'shows deprecation but still accepts strings enclosed with double quotes' do
+      expect_any_instance_of(::Magick::Image::Info).to receive(:size=).once.with("200x200")
+      expect(ActiveSupport::Deprecation).to receive(:warn).with(any_args)
+      instance.manipulate! :read => {:size => %{"200x200"}}
+    end
+
+    it 'shows deprecation but still accepts strings enclosed with single quotes' do
+      expect_any_instance_of(::Magick::Image::Info).to receive(:size=).once.with("200x200")
+      expect(ActiveSupport::Deprecation).to receive(:warn).with(any_args)
+      instance.manipulate! :read => {:size => %{'200x200'}}
+    end
+
+    it 'does not allow arbitrary code execution' do
+      expect_any_instance_of(Kernel).not_to receive(:puts)
+      expect do
+        instance.manipulate! :read => {
+            :density => "1 }; raise; {"
+        }
+      end.to raise_error ArgumentError, /invalid density geometry/
+    end
+
+    it 'does not allow invocation of non-public methods' do
+      module Kernel
+        private def foo=(value); raise; end
+      end
+      expect do
+        instance.manipulate! :read => {
+            :foo => "1"
+        }
+      end.to raise_error NoMethodError, /private method `foo=' called/
     end
   end
 
```
