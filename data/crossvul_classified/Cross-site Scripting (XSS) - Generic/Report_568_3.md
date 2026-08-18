# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 568_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `568_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 175-215 of the vulnerable file.

        run ExceptionSpec::ErrorHashApp
      end
    end
    it 'is possible to return hash errors in json format' do
      get '/'
      expect(['{"error":"rain!","detail":"missing widget"}',
              '{"detail":"missing widget","error":"rain!"}']).to include(last_response.body)
    end
  end

  context do
    subject do
      Rack::Builder.app do
        use Spec::Support::EndpointFaker
        use Grape::Middleware::Error, rescue_all: true, format: :jsonapi
        run ExceptionSpec::ExceptionApp
      end
    end
    it 'is possible to return errors in jsonapi format' do
      get '/'
      expect(last_response.body).to eq('{"error":"rain!"}')
    end
  end

  context do
    subject do
      Rack::Builder.app do
        use Spec::Support::EndpointFaker
        use Grape::Middleware::Error, rescue_all: true, format: :jsonapi
        run ExceptionSpec::ErrorHashApp
      end
    end

    it 'is possible to return hash errors in jsonapi format' do
      get '/'
      expect(['{"error":"rain!","detail":"missing widget"}',
              '{"detail":"missing widget","error":"rain!"}']).to include(last_response.body)
    end
  end

  context do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -192,7 +192,7 @@
     end
     it 'is possible to return errors in jsonapi format' do
       get '/'
-      expect(last_response.body).to eq('{"error":"rain!"}')
+      expect(last_response.body).to eq('{&quot;error&quot;:&quot;rain!&quot;}')
     end
   end
 
@@ -207,8 +207,8 @@
 
     it 'is possible to return hash errors in jsonapi format' do
       get '/'
-      expect(['{"error":"rain!","detail":"missing widget"}',
-              '{"detail":"missing widget","error":"rain!"}']).to include(last_response.body)
+      expect(['{&quot;error&quot;:&quot;rain!&quot;,&quot;detail&quot;:&quot;missing widget&quot;}',
+              '{&quot;detail&quot;:&quot;missing widget&quot;,&quot;error&quot;:&quot;rain!&quot;}']).to include(last_response.body)
     end
   end
 
@@ -258,7 +258,7 @@
     end
     it 'is possible to specify a custom formatter' do
       get '/'
-      expect(last_response.body).to eq('{:custom_formatter=>"rain!"}')
+      expect(last_response.body).to eq('{:custom_formatter=&gt;&quot;rain!&quot;}')
     end
   end
 
```
