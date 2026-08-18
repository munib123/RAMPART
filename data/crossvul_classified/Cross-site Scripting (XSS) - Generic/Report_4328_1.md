# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4328_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4328_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 142-182 of the vulnerable file.


        $this->asEditor();
        $page = Page::first();

        foreach ($checks as $check) {
            $page->html = $check;
            $page->save();

            $pageView = $this->get($page->getUrl());
            $pageView->assertStatus(200);
            $pageView->assertElementNotContains('.page-content', '<iframe>');
            $pageView->assertElementNotContains('.page-content', '</iframe>');
            $pageView->assertElementNotContains('.page-content', 'src=');
            $pageView->assertElementNotContains('.page-content', 'javascript:');
            $pageView->assertElementNotContains('.page-content', 'data:');
            $pageView->assertElementNotContains('.page-content', 'base64');
        }

    }

    public function test_page_inline_on_attributes_removed_by_default()
    {
        $this->asEditor();
        $page = Page::first();
        $script = '<p onmouseenter="console.log(\'test\')">Hello</p>';
        $page->html = "escape {$script}";
        $page->save();

        $pageView = $this->get($page->getUrl());
        $pageView->assertStatus(200);
        $pageView->assertDontSee($script);
        $pageView->assertSee('<p>Hello</p>');
    }

    public function test_more_complex_inline_on_attributes_escaping_scenarios()
    {
        $checks = [
            '<p onclick="console.log(\'test\')">Hello</p>',
            '<div>Lorem ipsum dolor sit amet.</div><p onclick="console.log(\'test\')">Hello</p>',
            '<div>Lorem ipsum dolor sit amet.<p onclick="console.log(\'test\')">Hello</p></div>',
            '<div><div><div><div>Lorem ipsum dolor sit amet.<p onclick="console.log(\'test\')">Hello</p></div></div></div></div>',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -159,6 +159,72 @@
 
     }
 
+    public function test_javascript_uri_links_are_removed()
+    {
+        $checks = [
+            '<a id="xss" href="javascript:alert(document.cookie)>Click me</a>',
+            '<a id="xss" href="javascript: alert(document.cookie)>Click me</a>'
+        ];
+
+        $this->asEditor();
+        $page = Page::first();
+
+        foreach ($checks as $check) {
+            $page->html = $check;
+            $page->save();
+
+            $pageView = $this->get($page->getUrl());
+            $pageView->assertStatus(200);
+            $pageView->assertElementNotContains('.page-content', '<a id="xss">');
+            $pageView->assertElementNotContains('.page-content', 'href=javascript:');
+        }
+    }
+    public function test_form_actions_with_javascript_are_removed()
+    {
+        $checks = [
+            '<form><input id="xss" type=submit formaction=javascript:alert(document.domain) value=Submit><input></form>',
+            '<form ><button id="xss" formaction=javascript:alert(document.domain)>Click me</button></form>',
+            '<form id="xss" action=javascript:alert(document.domain)><input type=submit value=Submit></form>'
+        ];
+
+        $this->asEditor();
+        $page = Page::first();
+
+        foreach ($checks as $check) {
+            $page->html = $check;
+            $page->save();
+
+            $pageView = $this->get($page->getUrl());
+            $pageView->assertStatus(200);
+            $pageView->assertElementNotContains('.page-content', '<button id="xss"');
+            $pageView->assertElementNotContains('.page-content', '<input id="xss"');
+            $pageView->assertElementNotContains('.page-content', '<form id="xss"');
+            $pageView->assertElementNotContains('.page-content', 'action=javascript:');
+            $pageView->assertElementNotContains('.page-content', 'formaction=javascript:');
+        }
+    }
+    
+    public function test_metadata_redirects_are_removed()
+    {
+        $checks = [
+            '<meta http-equiv="refresh" content="0; url=//external_url">',
+        ];
+
+        $this->asEditor();
+        $page = Page::first();
+
+        foreach ($checks as $check) {
+            $page->html = $check;
+            $page->save();
+
+            $pageView = $this->get($page->getUrl());
+            $pageView->assertStatus(200);
+            $pageView->assertElementNotContains('.page-content', '<meta>');
+            $pageView->assertElementNotContains('.page-content', '</meta>');
+            $pageView->assertElementNotContains('.page-content', 'content=');
+            $pageView->assertElementNotContains('.page-content', 'external_url');
+        }
+    }
     public function test_page_inline_on_attributes_removed_by_default()
     {
         $this->asEditor();
```
