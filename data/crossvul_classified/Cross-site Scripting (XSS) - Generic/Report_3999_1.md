# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3999_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3999_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 531-573 of the vulnerable file.


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
                    $dump .= '<!-- ' . htmlspecialchars($node->nodeName, ENT_QUOTES, $this->config['charset']) . ' ignored -->';
                    $dump .= $this->dumpHtml($node, $level); // ignore tags not its content
                }
                break;

            case XML_CDATA_SECTION_NODE:
                $dump .= $node->nodeValue;
                break;

            case XML_TEXT_NODE:
                $dump .= htmlspecialchars($node->nodeValue, ENT_COMPAT | ENT_HTML401 | ENT_SUBSTITUTE, $this->config['charset']);
                break;

            case XML_HTML_DOCUMENT_NODE:
                $dump .= $this->dumpHtml($node, $level);
                break;
            }
        }
        while($node = $node->nextSibling);

        return $dump;
    }

    /**
     * Main function, give it untrusted HTML, tell it if you allow loading
     * remote images and give it a map to convert "cid:" urls.
     *
     * @param string $html HTML content
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -548,9 +548,6 @@
                 break;
 
             case XML_CDATA_SECTION_NODE:
-                $dump .= $node->nodeValue;
-                break;
-
             case XML_TEXT_NODE:
                 $dump .= htmlspecialchars($node->nodeValue, ENT_COMPAT | ENT_HTML401 | ENT_SUBSTITUTE, $this->config['charset']);
                 break;
```
