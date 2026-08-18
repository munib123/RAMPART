# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3821_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3821_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 80-120 of the vulnerable file.


        $html = rcmail_html4inline($washed, 'foo');
        $this->assertNotRegExp('/onclick="return rcmail.command(\'compose\',\'xss@somehost.net\',this)"/', $html, "Clean mailto links");
        $this->assertNotRegExp('/alert/', $html, "Remove alerts");
    }

    /**
     * Test HTML sanitization to fix the CSS Expression Input Validation Vulnerability
     * reported at http://www.securityfocus.com/bid/26800/
     */
    function test_html_xss2()
    {
        $part = $this->get_html_part('src/BID-26800.txt');
        $washed = rcmail_html4inline(rcmail_print_body($part, array('safe' => true)), 'dabody', '', $attr, true);

        $this->assertNotRegExp('/alert|expression|javascript|xss/', $washed, "Remove evil style blocks");
        $this->assertNotRegExp('/font-style:italic/', $washed, "Allow valid styles");
    }

    /**
     * Test washtml class on non-unicode characters (#1487813)
     */
    function test_washtml_utf8()
    {
        $part = $this->get_html_part('src/invalidchars.html');
        $washed = rcmail_print_body($part);

        $this->assertRegExp('/<p>символ<\/p>/', $washed, "Remove non-unicode characters from HTML message body");
    }

    /**
     * Test links pattern replacements in plaintext messages
     */
    function test_plaintext()
    {
        $part = new rcube_message_part;
        $part->ctype_primary = 'text';
        $part->ctype_secondary = 'plain';
        $part->body = quoted_printable_decode(file_get_contents(TESTS_DIR . 'src/plainbody.txt'));
        $html = rcmail_print_body($part, array('safe' => true));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,6 +97,20 @@
     }
 
     /**
+     * Test the elimination of some XSS vulnerabilities
+     */
+    function test_html_xss3()
+    {
+        // #1488850
+        $html = '<p><a href="data:text/html,&lt;script&gt;alert(document.cookie)&lt;/script&gt;">Firefox</a>'
+            .'<a href="vbscript:alert(document.cookie)">Internet Explorer</a></p>';
+        $washed = rcmail_wash_html($html, array('safe' => true), array());
+
+        $this->assertNotRegExp('/data:text/', $washed, "Remove data:text/html links");
+        $this->assertNotRegExp('/vbscript:/', $washed, "Remove vbscript: links");
+    }
+
+    /**
      * Test washtml class on non-unicode characters (#1487813)
      */
     function test_washtml_utf8()
```
