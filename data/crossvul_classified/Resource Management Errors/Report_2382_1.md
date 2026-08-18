# CrossVul Fix Pair: Resource Management Errors in ruby
**Pair ID:** 2382_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2382_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```ruby
Lines 3-32 of the vulnerable file.

describe Raven::OkJson do

  ['foo', :foo].each do |obj|
    it "works with #{obj.class} keys" do
      expect(Raven::OkJson.encode(obj => 'bar')).to eq '{"foo":"bar"}'
    end

    it "works with #{obj.class} values" do
      expect(Raven::OkJson.encode('bar' => obj)).to eq '{"bar":"foo"}'
    end

    it "works with an array of #{obj.class}s" do
      expect(Raven::OkJson.encode('bar' => [obj])).to eq '{"bar":["foo"]}'
    end

    it "works with a hash of #{obj.class}s" do
      expect(Raven::OkJson.encode('bar' => {obj => obj})).to eq '{"bar":{"foo":"foo"}}'
    end
  end

  it 'parses zero-leading exponent numbers correctly' do
    expect(Raven::OkJson.decode("[123e090]")).to eq [123000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]
  end

  it 'it raises the correct error on strings that look like incomplete objects' do
    expect{Raven::OkJson.decode("{")}.to raise_error(Raven::OkJson::Error)
    expect{Raven::OkJson.decode("[")}.to raise_error(Raven::OkJson::Error)
  end

end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,8 +20,8 @@
     end
   end
 
-  it 'parses zero-leading exponent numbers correctly' do
-    expect(Raven::OkJson.decode("[123e090]")).to eq [123000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]
+  it 'does not parse scientific notation' do
+    expect(Raven::OkJson.decode("[123e090]")).to eq ["123e090"]
   end
 
   it 'it raises the correct error on strings that look like incomplete objects' do
```
