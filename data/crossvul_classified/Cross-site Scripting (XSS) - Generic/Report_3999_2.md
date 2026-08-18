# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3999_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3999_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 489-509 of the vulnerable file.


        $this->assertContains('>First line', $washed);

        $html   = '<html><head></head>First line<br />Second line</html>';
        $washed = $washer->wash($html);

        $this->assertContains('First line', $washed);

        // Not really valid HTML, but because its common in email world
        // and because it works with DOMDocument, we make sure its supported
        $html   = 'First line<br /><html><body>Second line';
        $washed = $washer->wash($html);

        $this->assertContains('First line', $washed);

        $html   = 'First line<br /><html>Second line';
        $washed = $washer->wash($html);

        $this->assertContains('First line', $washed);
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -506,4 +506,17 @@
 
         $this->assertContains('First line', $washed);
     }
+
+    /**
+     * Test CDATA cleanup
+     */
+    function test_cdata()
+    {
+        $html = '<p><![CDATA[<script>alert(document.cookie)</script>]]></p>';
+
+        $washer = new rcube_washtml;
+        $washed = $washer->wash($html);
+
+        $this->assertTrue(strpos($washed, '<script>') === false, "CDATA content");
+    }
 }
```
