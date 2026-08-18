# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5597_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5597_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 206-251 of the vulnerable file.

      @request.send(:format_from_mimetype, "application/atom+xml").should be_nil
    end

    it "returns nil when using a default parser" do
      @request.options[:parser] = lambda {}
      @request.send(:format_from_mimetype, "text/json").should be_nil
    end
  end

  describe 'parsing responses' do
    it 'should handle xml automatically' do
      xml = %q[<books><book><id>1234</id><name>Foo Bar!</name></book></books>]
      @request.options[:format] = :xml
      @request.send(:parse_response, xml).should == {'books' => {'book' => {'id' => '1234', 'name' => 'Foo Bar!'}}}
    end

    it 'should handle json automatically' do
      json = %q[{"books": {"book": {"name": "Foo Bar!", "id": "1234"}}}]
      @request.options[:format] = :json
      @request.send(:parse_response, json).should == {'books' => {'book' => {'id' => '1234', 'name' => 'Foo Bar!'}}}
    end

    it 'should handle yaml automatically' do
      yaml = "books: \n  book: \n    name: Foo Bar!\n    id: \"1234\"\n"
      @request.options[:format] = :yaml
      @request.send(:parse_response, yaml).should == {'books' => {'book' => {'id' => '1234', 'name' => 'Foo Bar!'}}}
    end

    it "should include any HTTP headers in the returned response" do
      @request.options[:format] = :html
      response = stub_response "Content"
      response.initialize_http_header("key" => "value")

      @request.perform.headers.should == { "key" => ["value"] }
    end

    describe 'with non-200 responses' do
      context "3xx responses" do
        it 'returns a valid object for 304 not modified' do
          stub_response '', 304
          resp = @request.perform
          resp.code.should == 304
          resp.body.should == ''
          resp.should be_nil
        end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -223,12 +223,6 @@
       json = %q[{"books": {"book": {"name": "Foo Bar!", "id": "1234"}}}]
       @request.options[:format] = :json
       @request.send(:parse_response, json).should == {'books' => {'book' => {'id' => '1234', 'name' => 'Foo Bar!'}}}
-    end
-
-    it 'should handle yaml automatically' do
-      yaml = "books: \n  book: \n    name: Foo Bar!\n    id: \"1234\"\n"
-      @request.options[:format] = :yaml
-      @request.send(:parse_response, yaml).should == {'books' => {'book' => {'id' => '1234', 'name' => 'Foo Bar!'}}}
     end
 
     it "should include any HTTP headers in the returned response" do
```
