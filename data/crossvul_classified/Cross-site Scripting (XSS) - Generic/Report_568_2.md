# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 568_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `568_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 2125-2165 of the vulnerable file.

        'some binary content'
      end
      get '/excel.xls'
      expect(last_response.content_type).to eq('application/vnd.ms-excel')
    end
    it 'allows to override content-type' do
      subject.get :content do
        content_type 'text/javascript'
        'var x = 1;'
      end
      get '/content'
      expect(last_response.content_type).to eq('text/javascript')
    end
    it 'removes existing content types' do
      subject.content_type :xls, 'application/vnd.ms-excel'
      subject.get :excel do
        'some binary content'
      end
      get '/excel.json'
      expect(last_response.status).to eq(406)
      expect(last_response.body).to eq("The requested format 'txt' is not supported.")
    end
  end

  describe '.formatter' do
    context 'multiple formatters' do
      before :each do
        subject.formatter :json, ->(object, _env) { "{\"custom_formatter\":\"#{object[:some]}\"}" }
        subject.formatter :txt, ->(object, _env) { "custom_formatter: #{object[:some]}" }
        subject.get :simple do
          { some: 'hash' }
        end
      end
      it 'sets one formatter' do
        get '/simple.json'
        expect(last_response.body).to eql '{"custom_formatter":"hash"}'
      end
      it 'sets another formatter' do
        get '/simple.txt'
        expect(last_response.body).to eql 'custom_formatter: hash'
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2142,7 +2142,11 @@
       end
       get '/excel.json'
       expect(last_response.status).to eq(406)
-      expect(last_response.body).to eq("The requested format 'txt' is not supported.")
+      if ActiveSupport::VERSION::MAJOR == 3
+        expect(last_response.body).to eq('The requested format &#x27;txt&#x27; is not supported.')
+      else
+        expect(last_response.body).to eq('The requested format &#39;txt&#39; is not supported.')
+      end
     end
   end
 
@@ -3524,7 +3528,27 @@
       end
       get '/something'
       expect(last_response.status).to eq(406)
-      expect(last_response.body).to eq("{\"error\":\"The requested format 'txt' is not supported.\"}")
+      if ActiveSupport::VERSION::MAJOR == 3
+        expect(last_response.body).to eq('{&quot;error&quot;:&quot;The requested format &#x27;txt&#x27; is not supported.&quot;}')
+      else
+        expect(last_response.body).to eq('{&quot;error&quot;:&quot;The requested format &#39;txt&#39; is not supported.&quot;}')
+      end
+    end
+  end
+
+  context 'with unsafe HTML format specified' do
+    it 'escapes the HTML' do
+      subject.content_type :json, 'application/json'
+      subject.get '/something' do
+        'foo'
+      end
+      get '/something?format=<script>blah</script>'
+      expect(last_response.status).to eq(406)
+      if ActiveSupport::VERSION::MAJOR == 3
+        expect(last_response.body).to eq('The requested format &#x27;&lt;script&gt;blah&lt;/script&gt;&#x27; is not supported.')
+      else
+        expect(last_response.body).to eq('The requested format &#39;&lt;script&gt;blah&lt;/script&gt;&#39; is not supported.')
+      end
     end
   end
 
```
