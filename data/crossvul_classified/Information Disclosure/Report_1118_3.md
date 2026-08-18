# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 1118_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1118_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-31 of the vulnerable file.

# frozen_string_literal: true

require 'minitest/global_expectations/autorun'
require 'thread'
require 'rack/lint'
require 'rack/mock'
require 'rack/session/pool'

describe Rack::Session::Pool do
  session_key = Rack::Session::Pool::DEFAULT_OPTIONS[:key]
  session_match = /#{session_key}=[0-9a-fA-F]+;/

  incrementor = lambda do |env|
    env["rack.session"]["counter"] ||= 0
    env["rack.session"]["counter"] += 1
    Rack::Response.new(env["rack.session"].inspect).to_a
  end

  session_id = Rack::Lint.new(lambda do |env|
    Rack::Response.new(env["rack.session"].inspect).to_a
  end)

  nothing = Rack::Lint.new(lambda do |env|
    Rack::Response.new("Nothing").to_a
  end)

  drop_session = Rack::Lint.new(lambda do |env|
    env['rack.session.options'][:drop] = true
    incrementor.call(env)
  end)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
 
 describe Rack::Session::Pool do
   session_key = Rack::Session::Pool::DEFAULT_OPTIONS[:key]
-  session_match = /#{session_key}=[0-9a-fA-F]+;/
+  session_match = /#{session_key}=([0-9a-fA-F]+);/
 
   incrementor = lambda do |env|
     env["rack.session"]["counter"] ||= 0
@@ -16,7 +16,7 @@
     Rack::Response.new(env["rack.session"].inspect).to_a
   end
 
-  session_id = Rack::Lint.new(lambda do |env|
+  get_session_id = Rack::Lint.new(lambda do |env|
     Rack::Response.new(env["rack.session"].inspect).to_a
   end)
 
@@ -143,6 +143,43 @@
     res1["Set-Cookie"].must_be_nil
     res1.body.must_equal '{"counter"=>1}'
     pool.pool.size.must_equal 1
+  end
+
+  it "can read the session with the legacy id" do
+    pool = Rack::Session::Pool.new(incrementor)
+    req = Rack::MockRequest.new(pool)
+
+    res0 = req.get("/")
+    cookie = res0["Set-Cookie"]
+    session_id = Rack::Session::SessionId.new cookie[session_match, 1]
+    ses0 = pool.pool[session_id.private_id]
+    pool.pool[session_id.public_id] = ses0
+    pool.pool.delete(session_id.private_id)
+
+    res1 = req.get("/", "HTTP_COOKIE" => cookie)
+    res1["Set-Cookie"].must_be_nil
+    res1.body.must_equal '{"counter"=>2}'
+    pool.pool[session_id.private_id].wont_be_nil
+  end
+
+  it "drops the session in the legacy id as well" do
+    pool = Rack::Session::Pool.new(incrementor)
+    req = Rack::MockRequest.new(pool)
+    drop = Rack::Utils::Context.new(pool, drop_session)
+    dreq = Rack::MockRequest.new(drop)
+
+    res0 = req.get("/")
+    cookie = res0["Set-Cookie"]
+    session_id = Rack::Session::SessionId.new cookie[session_match, 1]
+    ses0 = pool.pool[session_id.private_id]
+    pool.pool[session_id.public_id] = ses0
+    pool.pool.delete(session_id.private_id)
+
+    res2 = dreq.get("/", "HTTP_COOKIE" => cookie)
+    res2["Set-Cookie"].must_be_nil
+    res2.body.must_equal '{"counter"=>2}'
+    pool.pool[session_id.private_id].must_be_nil
+    pool.pool[session_id.public_id].must_be_nil
   end
 
   # anyone know how to do this better?
@@ -193,7 +230,7 @@
   end
 
   it "does not return a cookie if cookie was not written (only read)" do
-    app = Rack::Session::Pool.new(session_id)
+    app = Rack::Session::Pool.new(get_session_id)
     res = Rack::MockRequest.new(app).get("/")
     res["Set-Cookie"].must_be_nil
   end
```
