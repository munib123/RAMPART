# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 4983_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4983_4`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 110-150 of the vulnerable file.

    it "should change indirection name to 'status' if the http method is a GET and the indirection name is statuses" do
      expect(handler.uri2indirection("GET", "#{master_url_prefix}/statuses/bar", params)[0].name).to eq(:status)
    end

    it "should change indirection name to 'node' if the http method is a GET and the indirection name is nodes" do
      expect(handler.uri2indirection("GET", "#{master_url_prefix}/nodes/bar", params)[0].name).to eq(:node)
    end

    it "should choose 'delete' as the indirection method if the http method is a DELETE and the indirection name is singular" do
      expect(handler.uri2indirection("DELETE", "#{master_url_prefix}/node/bar", params)[1]).to eq(:destroy)
    end

    it "should choose 'save' as the indirection method if the http method is a PUT and the indirection name is singular" do
      expect(handler.uri2indirection("PUT", "#{master_url_prefix}/node/bar", params)[1]).to eq(:save)
    end

    it "should fail if an indirection method cannot be picked" do
      expect(lambda { handler.uri2indirection("UPDATE", "#{master_url_prefix}/node/bar", params) }).to raise_error(ArgumentError)
    end

    it "should URI unescape the indirection key" do
      escaped = URI.escape("foo bar")
      indirection, method, key, final_params = handler.uri2indirection("GET", "#{master_url_prefix}/node/#{escaped}", params)
      expect(key).to eq("foo bar")
    end

    it "should pass through a proper environment param in a call to check_authorization" do
      handler.expects(:check_authorization).with(anything,
                                                 anything,
                                                 all_of(
                                                   has_entry(:environment,
                                                             is_a(Puppet::Node::Environment)),
                                                   has_entry(:environment,
                                                             responds_with(:name,
                                                                           :env))))
      handler.uri2indirection("GET", "#{master_url_prefix}/node/bar", params)
    end

    it "should not pass through an environment to check_authorization and fail if the environment is unknown" do
      handler.expects(:check_authorization).with(anything,
                                                 anything,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -127,22 +127,17 @@
       expect(lambda { handler.uri2indirection("UPDATE", "#{master_url_prefix}/node/bar", params) }).to raise_error(ArgumentError)
     end
 
-    it "should URI unescape the indirection key" do
+    it "should not URI unescape the indirection key" do
       escaped = URI.escape("foo bar")
-      indirection, method, key, final_params = handler.uri2indirection("GET", "#{master_url_prefix}/node/#{escaped}", params)
-      expect(key).to eq("foo bar")
-    end
-
-    it "should pass through a proper environment param in a call to check_authorization" do
-      handler.expects(:check_authorization).with(anything,
-                                                 anything,
-                                                 all_of(
-                                                   has_entry(:environment,
-                                                             is_a(Puppet::Node::Environment)),
-                                                   has_entry(:environment,
-                                                             responds_with(:name,
-                                                                           :env))))
-      handler.uri2indirection("GET", "#{master_url_prefix}/node/bar", params)
+      indirection, _, key, _ = handler.uri2indirection("GET", "#{master_url_prefix}/node/#{escaped}", params)
+      expect(key).to eq(escaped)
+    end
+
+    it "should not unescape the URI passed through in a call to check_authorization" do
+      key_escaped = URI.escape("foo bar")
+      uri_escaped = "#{master_url_prefix}/node/#{key_escaped}"
+      handler.expects(:check_authorization).with(anything, uri_escaped, anything)
+      indirection, _, _, _ = handler.uri2indirection("GET", uri_escaped, params)
     end
 
     it "should not pass through an environment to check_authorization and fail if the environment is unknown" do
@@ -153,6 +148,19 @@
                                               "#{master_url_prefix}/node/bar",
                                               {:environment => 'bogus'}) }).to raise_error(ArgumentError)
     end
+
+    it "should not URI unescape the indirection key as passed through to a call to check_authorization" do
+      handler.expects(:check_authorization).with(anything,
+                                                 anything,
+                                                 all_of(
+                                                     has_entry(:environment,
+                                                               is_a(Puppet::Node::Environment)),
+                                                     has_entry(:environment,
+                                                               responds_with(:name,
+                                                                             :env))))
+      handler.uri2indirection("GET", "#{master_url_prefix}/node/bar", params)
+    end
+
   end
 
   describe "when converting a request into a URI" do
```
