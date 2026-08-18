# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5100_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5100_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 122-162 of the vulnerable file.

            array('<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>', ''),
            array("<HTML xmlns:xss>\n<?import namespace=\"xss\" implementation=\"http://ha.ckers.org/xss.htc\">\n<xss:xss>XSS</xss:xss>\n</HTML>", '<xss>XSS</xss>'),
            array("<XML ID=I><X><C><![CDATA[<IMG SRC=\"javas]]><![CDATA[cript:alert('XSS');\">]]>\n</C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>", '<span datasrc="#I" datafld="C" dataformatas="HTML"/>'),
            array("<XML ID=\"xss\"><I><B>&lt;IMG SRC=\"javas<!-- -->cript:alert('XSS')\"&gt;</B></I></XML>\n<SPAN DATASRC=\"#xss\" DATAFLD=\"B\" DATAFORMATAS=\"HTML\"></SPAN>", '<span datasrc="#xss" datafld="B" dataformatas="HTML"/>'),
            array("<XML SRC=\"xsstest.xml\" ID=I></XML>\n<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>", '<span datasrc="#I" datafld="C" dataformatas="HTML"/>'),
            array("<HTML><BODY><?xml:namespace prefix=\"t\" ns=\"urn:schemas-microsoft-com:time\"><?import namespace=\"t\" implementation=\"#default#time2\">\n<t:set attributeName=\"innerHTML\" to=\"XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;\"></BODY></HTML>", "<?xml:namespace prefix=\"t\" ns=\"urn:schemas-microsoft-com:time\"?><?import namespace=\"t\" implementation=\"#default#time2\"?>"),
            array('<SCRIPT SRC="http://ha.ckers.org/xss.jpg"><SCRIPT>', ''),
            array('<IMG SRC="javascript:alert(\'XSS\')"', '<img/>'),
            array('<SCRIPT a=">" SRC="http://xss.com/a.js"></SCRIPT>', ''),
            array('<SCRIPT =">" SRC="http://xss.com/a.js"></SCRIPT>', ''),
            array('<SCRIPT a=">" \'\' SRC="http://xss.com/a.js"></SCRIPT>', ''),
            array('<SCRIPT "a=\'>\'" SRC="http://xss.com/a.js"></SCRIPT>', ''),
            array('<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>', ''),
            array('<SCRIPT a=">\'>" SRC="http://ha.ckers.org/xss.js"></SCRIPT>', ''),
            array('<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/a.js"></SCRIPT>', '<p>PT SRC="http://ha.ckers.org/a.js"&gt;</p>'),
            array('<a href="data:text/html;base64,PGh0bWw+PGhlYWQ+PHRpdGxlPnRlc3Q8L3RpdGxlPjwvaGVhZD48Ym9keT48c2NyaXB0PmFsZXJ0KCd4c3M6ICcgKyBkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+PC9ib2R5PjwvaHRtbD4=" href="data:text/html;base64,PGh0bWw+PGhlYWQ+PHRpdGxlPnRlc3Q8L3RpdGxlPjwvaGVhZD48Ym9keT48c2NyaXB0PmFsZXJ0KCd4c3M6ICcgKyBkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+PC9ib2R5PjwvaHRtbD4=">Click me</a>', '<a>Click me</a>'),
            array('<a href="data:text/html;base64,PGh0bWw+PGhlYWQ+PHRpdGxlPnRlc3Q8L3RpdGxlPjwvaGVhZD48Ym9keT48c2NyaXB0PmFsZXJ0KCd4c3M6ICcgKyBkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+PC9ib2R5PjwvaHRtbD4=">Click me</a>', '<a>Click me</a>'),
            array('<body/onload=alert(/xss/)>', ''),
            array('<img src=""> <BODY ONLOAD="a();"><SCRIPT>function a(){alert(\'XSS\');}</SCRIPT><"" />', '<img src=""/>'),
            array('<img src=\'blank.jpg\'style=\'width:expression(alert("xssed"))\'>', '<img src="blank.jpg"/>'),
            array($framedata, '')
        );
    }

    public function testStyleXss()
    {
        $tests = array(
            '<BASE HREF="javascript:alert(\'XSS\');//">' => ''
        );

        foreach ($tests as $key => $val) {
            $this->assertEquals(
                $val,
                Horde_Text_Filter::filter($key, 'xss', array(
                    'strip_styles' => false
                ))
            );
        }
    }

    public function testBug9567()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -139,7 +139,10 @@
             array('<body/onload=alert(/xss/)>', ''),
             array('<img src=""> <BODY ONLOAD="a();"><SCRIPT>function a(){alert(\'XSS\');}</SCRIPT><"" />', '<img src=""/>'),
             array('<img src=\'blank.jpg\'style=\'width:expression(alert("xssed"))\'>', '<img src="blank.jpg"/>'),
-            array($framedata, '')
+            array($framedata, ''),
+            array('<svg><a xlink:href="data:text/html,<script>alert(/XSS/)</script>"><rect width="1000" height="1000" fill="white"/></a></svg>', '<svg><a><rect width="1000" height="1000" fill="white"/></a></svg>'),
+            array('<math><a xlink:href="data:text/html,<script>alert(/XSS/)</script>">click</a></math>', '<math><a>click</a></math>'),
+            array('<form action="data:text/html,<script>alert(/XSS/)</script>"><button></form>', '<form><button/></form>'),
         );
     }
 
```
