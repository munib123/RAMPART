# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4221_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4221_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 299-339 of the vulnerable file.


        $exp = '<svg xmlns:cc="http://creativecommons.org/ns#" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns="http://www.w3.org/2000/svg" version="1.1" baseProfile="full" viewBox="0 0 100 100">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400" x-washed="onmouseover" />
  <text x="50" y="68" font-size="48" fill="#FFF" text-anchor="middle">410</text>
  <!-- script not allowed -->
  <text x="10" y="25">An example text</text>
  <a xlink:href="http://www.w.pl"><rect width="100%" height="100%" /></a>
  <!-- foreignObject ignored -->
  <set attributeName="onmouseover" x-washed="to" />
  <animate attributeName="onunload" x-washed="to" />
  <animate attributeName="xlink:href" begin="0" x-washed="from" />
</svg>';

        $washer = new rcube_washtml;
        $washed = $washer->wash($svg);

        $this->assertSame($washed, $exp, "SVG content");
    }

    /**
     * Test position:fixed cleanup - (#5264)
     */
    function test_style_wash_position_fixed()
    {
        $html = "<img style='position:fixed' /><img style=\"position:/**/ fixed; top:10px\" />";
        $exp  = "<img style=\"position: absolute\" /><img style=\"position: absolute; top: 10px\" />";

        $washer = new rcube_washtml;
        $washed = $washer->wash($html);

        $this->assertTrue(strpos($washed, $exp) !== false, "Position:fixed (#5264)");
    }

    /**
     * Test MathML cleanup
     */
    function test_wash_mathml()
    {
        $mathml = '<html><head><meta http-equiv="content-type" content="text/html; charset=utf-8"></head><body>
            <math><semantics>
                <mrow>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -308,6 +308,44 @@
   <animate attributeName="onunload" x-washed="to" />
   <animate attributeName="xlink:href" begin="0" x-washed="from" />
 </svg>';
+
+        $washer = new rcube_washtml;
+        $washed = $washer->wash($svg);
+
+        $this->assertSame($washed, $exp, "SVG content");
+    }
+
+    /**
+     * Test SVG cleanup
+     */
+    function test_wash_svg2()
+    {
+        $svg = '<head xmlns="&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;"><svg></svg></head>';
+        $exp = '<!-- html ignored --><!-- head ignored --><svg xmlns="http://www.w3.org/1999/xhtml"></svg>';
+
+        $washer = new rcube_washtml;
+        $washed = $washer->wash($svg);
+
+        $this->assertSame($washed, $exp, "SVG content");
+
+        $svg = '<head xmlns="&quot; onload=&quot;alert(document.domain)">Hello victim!<svg></svg></head>';
+        $exp = '<!-- html ignored --><!-- head ignored -->Hello victim!<svg xmlns="http://www.w3.org/1999/xhtml"></svg>';
+
+        $washer = new rcube_washtml;
+        $washed = $washer->wash($svg);
+
+        $this->assertSame($washed, $exp, "SVG content");
+
+        $svg = '<p>Hello victim!<svg xmlns="&quot; onload=&quot;alert(document.domain)"></svg></p>';
+        $exp = '<p>Hello victim!<svg /></p>';
+
+        $washer = new rcube_washtml;
+        $washed = $washer->wash($svg);
+
+        $this->assertSame($washed, $exp, "SVG content");
+
+        $svg = '<svg xmlns="&quot; onload=&quot;alert(document.domain)" />';
+        $exp = '<svg xmlns="&quot; onload=&quot;alert(document.domain)" />';
 
         $washer = new rcube_washtml;
         $washed = $washer->wash($svg);
```
