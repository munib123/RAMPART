# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 4983_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4983_5`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 46-86 of the vulnerable file.

        expect(@handler.headers(req)).to eq({"accept" => 'myaccept',
                                         "x-custom-header" => 'mycustom',
                                         "content-type" => nil })
      end
    end

    describe "and using the HTTP Handler interface" do
      it "should return the CONTENT_TYPE parameter as the content type header" do
        req = mk_req('/', 'CONTENT_TYPE' => 'mycontent')
        expect(@handler.headers(req)['content-type']).to eq("mycontent")
      end

      it "should use the REQUEST_METHOD as the http method" do
        req = mk_req('/', :method => 'MYMETHOD')
        expect(@handler.http_method(req)).to eq("MYMETHOD")
      end

      it "should return the request path as the path" do
        req = mk_req('/foo/bar')
        expect(@handler.path(req)).to eq("/foo/bar")
      end

      it "should return the request body as the body" do
        req = mk_req('/foo/bar', :input => 'mybody')
        expect(@handler.body(req)).to eq("mybody")
      end

      it "should return the an Puppet::SSL::Certificate instance as the client_cert" do
        req = mk_req('/foo/bar', 'SSL_CLIENT_CERT' => minimal_certificate.to_pem)
        expect(@handler.client_cert(req).content.to_pem).to eq(minimal_certificate.to_pem)
      end

      it "returns nil when SSL_CLIENT_CERT is empty" do
        req = mk_req('/foo/bar', 'SSL_CLIENT_CERT' => '')

        expect(@handler.client_cert(req)).to be_nil
      end

      it "should set the response's content-type header when setting the content type" do
        @header = mock 'header'
        @response.expects(:header).returns @header
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,6 +65,13 @@
         expect(@handler.path(req)).to eq("/foo/bar")
       end
 
+      it "should return the unescaped path for an escaped request path" do
+        unescaped_path = '/foo/bar baz'
+        escaped_path = URI.escape(unescaped_path)
+        req = mk_req(escaped_path)
+        expect(@handler.path(req)).to eq(unescaped_path)
+      end
+
       it "should return the request body as the body" do
         req = mk_req('/foo/bar', :input => 'mybody')
         expect(@handler.body(req)).to eq("mybody")
```
