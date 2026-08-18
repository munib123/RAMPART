# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1983_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1983_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 220-260 of the vulnerable file.

        $mod = rcube_utils::mod_css_styles(".test { position:/**/fixed; }", 'rcmbody');
        $this->assertEquals("#rcmbody .test { position: absolute; }", $mod, "Replace position:fixed with position:absolute (2)");

        // position: fixed (#6898)
        $mod = rcube_utils::mod_css_styles(".test { position : fixed; top: 0; }", 'rcmbody');
        $this->assertEquals("#rcmbody .test { position: absolute; top: 0; }", $mod, "Replace position:fixed with position:absolute (3)");
        $mod = rcube_utils::mod_css_styles(".test { position/**/: fixed; top: 0; }", 'rcmbody');
        $this->assertEquals("#rcmbody .test { position: absolute; top: 0; }", $mod, "Replace position:fixed with position:absolute (4)");
        $mod = rcube_utils::mod_css_styles(".test { position\n: fixed; top: 0; }", 'rcmbody');
        $this->assertEquals("#rcmbody .test { position: absolute; top: 0; }", $mod, "Replace position:fixed with position:absolute (5)");

        // allow data URIs with images (#5580)
        $mod = rcube_utils::mod_css_styles("body { background-image: url(data:image/png;base64,123); }", 'rcmbody');
        $this->assertContains("#rcmbody { background-image: url(data:image/png;base64,123);", $mod, "Data URIs in url() allowed [1]");
        $mod = rcube_utils::mod_css_styles("body { background-image: url(data:image/png;base64,123); }", 'rcmbody', true);
        $this->assertContains("#rcmbody { background-image: url(data:image/png;base64,123);", $mod, "Data URIs in url() allowed [2]");

        // Allow strict url()
        $mod = rcube_utils::mod_css_styles("body { background-image: url(http://example.com); }", 'rcmbody', true);
        $this->assertContains("#rcmbody { background-image: url(http://example.com);", $mod, "Strict URIs in url() allowed with \$allow_remote=true");
    }

    /**
     * rcube_utils::mod_css_styles()'s prefix argument handling
     */
    function test_mod_css_styles_prefix()
    {
        $css = '
            .one { font-size: 10pt; }
            .three.four { font-weight: bold; }
            #id1 { color: red; }
            #id2.class:focus { color: white; }
            .five:not(.test), { background: transparent; }
            div .six { position: absolute; }
            p > i { font-size: 120%; }
            div#some { color: yellow; }
            @media screen and (max-width: 699px) and (min-width: 520px) {
                li a.button { padding-left: 30px; }
            }
            :root * { color: red; }
            :root > * { top: 0; }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -237,6 +237,23 @@
         // Allow strict url()
         $mod = rcube_utils::mod_css_styles("body { background-image: url(http://example.com); }", 'rcmbody', true);
         $this->assertContains("#rcmbody { background-image: url(http://example.com);", $mod, "Strict URIs in url() allowed with \$allow_remote=true");
+
+        // XSS issue, HTML in 'content' property
+        $style = "body { content: '</style><img src onerror=\"alert(\'hello\');\">'; color: red; }";
+        $mod = rcube_utils::mod_css_styles($style, 'rcmbody', true);
+        $this->assertSame("#rcmbody { content: '';\n color: red;\n }", $mod);
+
+        $style = "body { content: '< page: ;/style>< page: ;img src onerror=\"alert(\'hello\');\">'; color: red; }";
+        $mod = rcube_utils::mod_css_styles($style, 'rcmbody', true);
+        $this->assertSame(
+            "#rcmbody { content: '< page: unset;/style>< page: unset;img src onerror=\"alert('hello');\">'; color: red; }",
+            str_replace("\n", '', $mod)
+        );
+
+        // Removing page: property
+        $style = "body { page: test; color: red; }";
+        $mod = rcube_utils::mod_css_styles($style, 'rcmbody', true);
+        $this->assertSame("#rcmbody { page: unset;\n color: red;\n }", $mod);
     }
 
     /**
```
