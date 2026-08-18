# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5597_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5597_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 138-171 of the vulnerable file.

    subject do
      HTTParty::Parser.new('body', nil)
    end

    it "parses xml with MultiXml" do
      MultiXml.should_receive(:parse).with('body')
      subject.send(:xml)
    end

    it "parses json with MultiJson" do
      MultiJson.should_receive(:load).with('body')
      subject.send(:json)
    end

    it "uses MultiJson.decode if MultiJson does not respond to adapter" do
      MultiJson.should_receive(:respond_to?).with(:adapter).and_return(false)
      MultiJson.should_receive(:decode).with('body')
      subject.send(:json)
    end

    it "parses yaml" do
      YAML.should_receive(:load).with('body')
      subject.send(:yaml)
    end

    it "parses html by simply returning the body" do
      subject.send(:html).should == 'body'
    end

    it "parses plain text by simply returning the body" do
      subject.send(:plain).should == 'body'
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,11 +155,6 @@
       subject.send(:json)
     end
 
-    it "parses yaml" do
-      YAML.should_receive(:load).with('body')
-      subject.send(:yaml)
-    end
-
     it "parses html by simply returning the body" do
       subject.send(:html).should == 'body'
     end
```
