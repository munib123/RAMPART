# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 1550_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1550_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 13-52 of the vulnerable file.

  end

  it "is on the attachment without being explicitly added" do
    assert Dummy.validators_on(:avatar).any?{ |validator| validator.kind == :media_type_spoof_detection }
  end

  it "is not on the attachment when explicitly rejected" do
    rebuild_model validate_media_type: false
    assert Dummy.validators_on(:avatar).none?{ |validator| validator.kind == :media_type_spoof_detection }
  end

  it "returns default error message for spoofed media type" do
    build_validator
    file = File.new(fixture_file("5k.png"), "rb")
    @dummy.avatar.assign(file)

    detector = mock("detector", :spoofed? => true)
    Paperclip::MediaTypeSpoofDetector.stubs(:using).returns(detector)
    @validator.validate(@dummy)

    assert_equal "has an extension that does not match its contents", @dummy.errors[:avatar].first
  end

  it "runs when attachment is dirty" do
    build_validator
    file = File.new(fixture_file("5k.png"), "rb")
    @dummy.avatar.assign(file)
    Paperclip::MediaTypeSpoofDetector.stubs(:using).returns(stub(:spoofed? => false))

    @dummy.valid?

    assert_received(Paperclip::MediaTypeSpoofDetector, :using){|e| e.once }
  end

  it "does not run when attachment is not dirty" do
    Paperclip::MediaTypeSpoofDetector.stubs(:using).never
    @dummy.valid?
    assert_received(Paperclip::MediaTypeSpoofDetector, :using){|e| e.never }
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,7 @@
     Paperclip::MediaTypeSpoofDetector.stubs(:using).returns(detector)
     @validator.validate(@dummy)
 
-    assert_equal "has an extension that does not match its contents", @dummy.errors[:avatar].first
+    assert_equal I18n.t("errors.messages.spoofed_media_type"), @dummy.errors[:avatar].first
   end
 
   it "runs when attachment is dirty" do
```
