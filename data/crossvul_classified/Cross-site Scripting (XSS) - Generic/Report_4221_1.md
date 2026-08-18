# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4221_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4221_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 504-544 of the vulnerable file.

                    if (!$uri) {
                        $dump .= '<!-- link ignored -->';
                        break;
                    }

                    $node->setAttribute('href', (string) $uri);
                }

                if ($callback = $this->handlers[$tagName]) {
                    $dump .= call_user_func($callback, $tagName,
                        $this->wash_attribs($node), $this->dumpHtml($node, $level), $this);
                }
                else if (isset($this->_html_elements[$tagName])) {
                    $content = $this->dumpHtml($node, $level);
                    $dump .= '<' . $node->nodeName;

                    if ($tagName == 'svg') {
                        $xpath = new DOMXPath($node->ownerDocument);
                        foreach ($xpath->query('namespace::*') as $ns) {
                            if ($ns->nodeName != 'xmlns:xml') {
                                $dump .= ' ' . $ns->nodeName . '="' . $ns->nodeValue . '"';
                            }
                        }
                    }
                    else if ($tagName == 'textarea' && strpos($content, '<') !== false) {
                        $content = htmlspecialchars($content, ENT_QUOTES | ENT_SUBSTITUTE, $this->config['charset']);
                    }

                    $dump .= $this->wash_attribs($node);

                    if ($content === '' && ($this->is_xml || isset($this->_void_elements[$tagName]))) {
                        $dump .= ' />';
                    }
                    else {
                        $dump .= '>' . $content . '</' . $node->nodeName . '>';
                    }
                }
                else if (isset($this->_ignore_elements[$tagName])) {
                    $dump .= '<!-- ' . htmlspecialchars($node->nodeName, ENT_QUOTES, $this->config['charset']) . ' not allowed -->';
                }
                else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -521,7 +521,10 @@
                         $xpath = new DOMXPath($node->ownerDocument);
                         foreach ($xpath->query('namespace::*') as $ns) {
                             if ($ns->nodeName != 'xmlns:xml') {
-                                $dump .= ' ' . $ns->nodeName . '="' . $ns->nodeValue . '"';
+                                $dump .= sprintf(' %s="%s"',
+                                    $ns->nodeName,
+                                    htmlspecialchars($ns->nodeValue, ENT_QUOTES, $this->config['charset'])
+                                );
                             }
                         }
                     }
@@ -588,7 +591,7 @@
         $this->max_nesting_level = (int) @ini_get('xdebug.max_nesting_level');
 
         // SVG need to be parsed as XML
-        $this->is_xml = stripos($html, '<html') === false && stripos($html, '<svg') !== false;
+        $this->is_xml = !preg_match('/<(html|head|body)/i', $html) && stripos($html, '<svg') !== false;
         $method       = $this->is_xml ? 'loadXML' : 'loadHTML';
 
         // DOMDocument does not support HTML5, try Masterminds parser if available
```
