# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 5763_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5763_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 33-73 of the vulnerable file.

      assert_equal 'baz', strategy.authorize_params['foo']
    end
    
    test 'should exclude top-level options that are not passed' do
      @options = { :authorize_options => [:bar] }
      refute_has_key :bar, strategy.authorize_params
      refute_has_key 'bar', strategy.authorize_params
    end
  end

  module CSRFAuthorizeParamsTests
    extend BlockTestHelper

    test 'should store random state in the session when none is present in authorize or request params' do
      assert_includes strategy.authorize_params.keys, 'state'
      refute_empty strategy.authorize_params['state']
      refute_empty strategy.session['omniauth.state']
      assert_equal strategy.authorize_params['state'], strategy.session['omniauth.state']
    end

    test 'should store state in the session when present in authorize params vs. a random one' do
      @options = { :authorize_params => { :state => 'bar' } }
      refute_empty strategy.authorize_params['state']
      assert_equal 'bar', strategy.authorize_params[:state]
      refute_empty strategy.session['omniauth.state']
      assert_equal 'bar', strategy.session['omniauth.state']
    end

    test 'should store state in the session when present in request params vs. a random one' do
      @request.stubs(:params).returns({ 'state' => 'foo' })
      refute_empty strategy.authorize_params['state']
      assert_equal 'foo', strategy.authorize_params[:state]
      refute_empty strategy.session['omniauth.state']
      assert_equal 'foo', strategy.session['omniauth.state']
    end
  end

  module TokenParamsTests
    extend BlockTestHelper
    
    test 'should include any authorize params passed in the :token_params option' do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,20 +50,20 @@
       assert_equal strategy.authorize_params['state'], strategy.session['omniauth.state']
     end
 
-    test 'should store state in the session when present in authorize params vs. a random one' do
+    test 'should not store state in the session when present in authorize params vs. a random one' do
       @options = { :authorize_params => { :state => 'bar' } }
       refute_empty strategy.authorize_params['state']
-      assert_equal 'bar', strategy.authorize_params[:state]
+      refute_equal 'bar', strategy.authorize_params[:state]
       refute_empty strategy.session['omniauth.state']
-      assert_equal 'bar', strategy.session['omniauth.state']
+      refute_equal 'bar', strategy.session['omniauth.state']
     end
 
-    test 'should store state in the session when present in request params vs. a random one' do
+    test 'should not store state in the session when present in request params vs. a random one' do
       @request.stubs(:params).returns({ 'state' => 'foo' })
       refute_empty strategy.authorize_params['state']
-      assert_equal 'foo', strategy.authorize_params[:state]
+      refute_equal 'foo', strategy.authorize_params[:state]
       refute_empty strategy.session['omniauth.state']
-      assert_equal 'foo', strategy.session['omniauth.state']
+      refute_equal 'foo', strategy.session['omniauth.state']
     end
   end
 
```
