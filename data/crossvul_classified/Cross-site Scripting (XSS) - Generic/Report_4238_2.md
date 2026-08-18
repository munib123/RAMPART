# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4238_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4238_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 300-340 of the vulnerable file.


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
     * Test SVG cleanup
     */
    function test_wash_svg2()
    {
        $svg = '<head xmlns="&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;"><svg></svg></head>';
        $exp = '<!-- html ignored --><!-- head ignored --><svg xmlns="http://www.w3.org/1999/xhtml"></svg>';

        $washer = new rcube_washtml;
        $washed = $washer->wash($svg);

        $this->assertSame($washed, $exp, "SVG content");

        $svg = '<head xmlns="&quot; onload=&quot;alert(document.domain)">Hello victim!<svg></svg></head>';
        $exp = '<!-- html ignored --><!-- head ignored -->Hello victim!<svg xmlns="http://www.w3.org/1999/xhtml"></svg>';

        $washer = new rcube_washtml;
        $washed = $washer->wash($svg);

        $this->assertSame($washed, $exp, "SVG content");

        $svg = '<p>Hello victim!<svg xmlns="&quot; onload=&quot;alert(document.domain)"></svg></p>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -317,41 +317,166 @@
     }
 
     /**
+     * Test cases for SVG tests
+     */
+    function data_wash_svg_tests()
+    {
+        $svg1 = "<svg id='x' width='100' height='100'><a xlink:href='javascript:alert(1)'><rect x='0' y='0' width='100' height='100' /></a></svg>";
+
+        return [
+            [
+                '<head xmlns="&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;"><svg></svg></head>',
+                '<!-- html ignored --><!-- head ignored --><svg xmlns="http://www.w3.org/1999/xhtml"></svg>'
+            ],
+            [
+                '<head xmlns="&quot; onload=&quot;alert(document.domain)">Hello victim!<svg></svg></head>',
+                '<!-- html ignored --><!-- head ignored -->Hello victim!<svg xmlns="http://www.w3.org/1999/xhtml"></svg>'
+            ],
+            [
+                '<p>Hello victim!<svg xmlns="&quot; onload=&quot;alert(document.domain)"></svg></p>',
+                '<p>Hello victim!<svg /></p>'
+            ],
+            [
+                '<html><p>Hello victim!<svg xmlns="&quot; onload=&quot;alert(document.domain)"></svg></p>',
+                '<!-- html ignored --><!-- body ignored --><p>Hello victim!<svg xmlns="http://www.w3.org/1999/xhtml"></svg></p>'
+            ],
+            [
+                '<svg xmlns="&quot; onload=&quot;alert(document.domain)" />',
+                '<svg xmlns="&quot; onload=&quot;alert(document.domain)" />'
+            ],
+            [
+                '<html><svg xmlns="&quot; onload=&quot;alert(document.domain)" />',
+                '<!-- html ignored --><!-- body ignored --><svg xmlns="http://www.w3.org/1999/xhtml"></svg>'
+            ],
+            [
+                '<svg><a xlink:href="javascript:alert(1)"><text x="20" y="20">XSS</text></a></svg>',
+                '<svg><a x-washed="xlink:href"><text x="20" y="20">XSS</text></a></svg>'
+            ],
+            [
+                '<html><svg><a xlink:href="javascript:alert(1)"><text x="20" y="20">XSS</text></a></svg>',
+                '<!-- html ignored --><!-- body ignored --><svg xmlns="http://www.w3.org/1999/xhtml"><a x-washed="xlink:href"><text x="20" y="20">XSS</text></a></svg>'
+            ],
+            [
+                '<svg><animate xlink:href="#xss" attributeName="href" values="javascript:alert(1)" />'
+                    . '<a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+                '<svg><!-- animate blocked --><a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+            ],
+            [
+                '<html><svg><animate xlink:href="#xss" attributeName="href" values="javascript:alert(1)" />'
+                    . '<a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+                '<!-- html ignored --><!-- body ignored --><svg xmlns="http://www.w3.org/1999/xhtml">'
+                    . '<!-- animate blocked --><a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+            ],
+            [
+                '<svg><animate xlink:href="#xss" attributeName="href" from="javascript:alert(1)" to="1" />'
+                    . '<a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+                '<svg><!-- animate blocked --><a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+            ],
+            [
+                '<svg><set xlink:href="#xss" attributeName="href" from="?" to="javascript:alert(1)" />'
+                    . '<a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+                '<svg><!-- set blocked --><a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+            ],
+            [
+                '<svg><animate xlink:href="#xss" attributename="href" dur="5s" repeatCount="indefinite" keytimes="0;0;1" values="https://portswigger.net?;javascript:alert(1);0" />'
+                    . '<a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+                '<svg><!-- animate blocked --><a id="xss"><text x="20" y="20">XSS</text></a></svg>',
+            ],
+            [
+                "<svg><use href=\"data:image/svg+xml,&lt;svg id='x' xmlns='http://www.w3.org/2000/svg' "
+                    . "xmlns:xlink='http://www.w3.org/1999/xlink' width='100' height='100'&gt;&lt;a xlink:href='javascript:alert(1)'&gt;"
+                    . "&lt;rect x='0' y='0' width='100' height='100' /&gt;&lt;/a&gt;&lt;/svg&gt;\"></use></svg>",
+                "<svg><use href=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53"
+                    . "My5vcmcvMTk5OS94bGluayIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBpZD0ie"
+                    . "CIgd2lkdGg9IjEwMCIgaGVpZ2h0PSIxMDAiPjxhIHgtd2FzaGVkPSJ4bGluazpocmVmIj48cmVjdC"
+                    . "B4PSIwIiB5PSIwIiB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgLz48L2E+PC9zdmc+\" /></svg>"
+            ],
+            [
+                "<svg><use href=\"data:image/svg+xml;base64," . base64_encode($svg1) . "\"></use></svg>",
+                "<svg><use href=\"data:image/svg+xml;base64,PHN2ZyBpZD0ieCIgd2lkdGg9IjEwMCIgaGVpZ2h"
+                    . "0PSIxMDAiPjxhIHgtd2FzaGVkPSJ4bGluazpocmVmIj48cmVjdCB4PSIwIiB5PSIwIiB3aWR0aD0"
+                    . "iMTAwIiBoZWlnaHQ9IjEwMCIgLz48L2E+PC9zdmc+\" /></svg>"
+            ],
+            [
+                '<svg><script href="data:text/javascript,alert(1)" /><text x="20" y="20">XSS</text></svg>',
+                '<svg><!-- script not allowed --><text x="20" y="20">XSS</text></svg>'
+            ],
+        ];
+    }
+
+    /**
      * Test SVG cleanup
-     */
-    function test_wash_svg2()
-    {
-        $svg = '<head xmlns="&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;"><svg></svg></head>';
-        $exp = '<!-- html ignored --><!-- head ignored --><svg xmlns="http://www.w3.org/1999/xhtml"></svg>';
-
-        $washer = new rcube_washtml;
-        $washed = $washer->wash($svg);
-
-        $this->assertSame($washed, $exp, "SVG content");
-
-        $svg = '<head xmlns="&quot; onload=&quot;alert(document.domain)">Hello victim!<svg></svg></head>';
-        $exp = '<!-- html ignored --><!-- head ignored -->Hello victim!<svg xmlns="http://www.w3.org/1999/xhtml"></svg>';
-
-        $washer = new rcube_washtml;
-        $washed = $washer->wash($svg);
-
-        $this->assertSame($washed, $exp, "SVG content");
-
-        $svg = '<p>Hello victim!<svg xmlns="&quot; onload=&quot;alert(document.domain)"></svg></p>';
-        $exp = '<p>Hello victim!<svg /></p>';
-
-        $washer = new rcube_washtml;
-        $washed = $washer->wash($svg);
-
-        $this->assertSame($washed, $exp, "SVG content");
-
-        $svg = '<svg xmlns="&quot; onload=&quot;alert(document.domain)" />';
-        $exp = '<svg xmlns="&quot; onload=&quot;alert(document.domain)" />';
-
-        $washer = new rcube_washtml;
-        $washed = $washer->wash($svg);
-
-        $this->assertSame($washed, $exp, "SVG content");
+     *
+     * @dataProvider data_wash_svg_tests
+     */
+    function test_wash_svg_tests($input, $expected)
+    {
+        $washer = new rcube_washtml;
+        $washed = $washer->wash($input);
+
+        $this->assertSame($expected, $washed, "SVG content");
+    }
+
+    /**
+     * Test cases for various XSS issues
+     */
+    function data_wash_xss_tests()
+    {
+        return [
+            [
+                '<html><base href="javascript:/a/-alert(1)///////"><a href="../lol/safari.html">test</a>',
+                '<!-- html ignored --><body><!-- base ignored --><a x-washed="href">test</a></body>'
+            ],
+            [
+                '<html><math><x href="javascript:alert(1)">blah</x>',
+                '<!-- html ignored --><body><math><!-- x ignored -->blah</math></body>'
+            ],
+            [
+                '<html><a href="j&#x61vascript:alert(1)">XSS</a>',
+                '<!-- html ignored --><body><a x-washed="href">XSS</a></body>'
+            ],
+            [
+                '<html><a href="&#x6a avascript:alert(1)">XSS</a>',
... (diff truncated)
```
