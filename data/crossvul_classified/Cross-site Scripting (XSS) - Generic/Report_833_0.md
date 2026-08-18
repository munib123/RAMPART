# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 833_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `833_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 51-94 of the vulnerable file.

                    if ($opening_tag[1] == $pos) continue;
                    if ($type == 'close') $counter--;
                    else $counter++;
                    if ($counter == 0) {
                        $pairs[] = array($opening_tag[1], $pos);
                        continue 2;
                    }
                }
            }
            foreach ($pairs as $pair) {
                $temp = substr($string, 0, $pair[0]);
                if ($this->__replacement[$trigger]['type'] == 'url') {
                    $data = substr($string, $pair[0] + $opening_len, $pair[1] - ($pair[0] + $opening_len));
                    if (empty($data)) {
                        $replacement = '';
                    } else {
                        if (!is_numeric($data) && ($trigger == 'event' || $trigger == 'thread')) {
                            $replacement = '%MALFORMED URL%';
                        } else {
                            if (filter_var(str_replace('$1', $data, $this->__replacement[$trigger]['url']), FILTER_VALIDATE_URL)) {
                                $replacement = $this->Html->link(
                                    str_replace('$1', $data, $this->__replacement[$trigger]['text']),
                                    str_replace('$1', $data, $this->__replacement[$trigger]['url'])
                                );
                            } else {
                                $replacement = '%MALFORMED URL%';
                            }
                        }
                    }
                } else {
                    $data = substr($string, $pair[0] + $opening_len, $pair[1] - ($pair[0] + $opening_len));
                    if (empty($data)) {
                        $replacement = '';
                    } else {
                        $replacement = str_replace('$1', $data, $this->__replacement[$trigger]['text']);
                    }
                }
                $temp .= $replacement;
                $temp .= substr($string, $pair[1] + $closing_len, strlen($string));
                $string = $temp;
            }
            return true;
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,10 +68,14 @@
                             $replacement = '%MALFORMED URL%';
                         } else {
                             if (filter_var(str_replace('$1', $data, $this->__replacement[$trigger]['url']), FILTER_VALIDATE_URL)) {
-                                $replacement = $this->Html->link(
-                                    str_replace('$1', $data, $this->__replacement[$trigger]['text']),
-                                    str_replace('$1', $data, $this->__replacement[$trigger]['url'])
-                                );
+                                if (substr($data, 0, 7) === 'http://' || substr($data, 0, 8) === 'https://') {
+                                    $replacement = $this->Html->link(
+                                        str_replace('$1', $data, $this->__replacement[$trigger]['text']),
+                                        str_replace('$1', $data, $this->__replacement[$trigger]['url'])
+                                    );
+                                } else {
+                                    $replacement = '%MALFORMED URL%';
+                                }
                             } else {
                                 $replacement = '%MALFORMED URL%';
                             }
```
