# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4239_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4239_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 373-413 of the vulnerable file.

            || ($src = $this->config['cid_map'][$this->config['base_url'].$uri])
        ) {
            return $src;
        }

        // allow url(#id) used in SVG
        if ($uri[0] == '#') {
            return $uri;
        }

        if (preg_match('/^(http|https|ftp):.+/i', $uri)) {
            if ($this->config['allow_remote']) {
                return $uri;
            }

            $this->extlinks = true;
            if ($blocked_source && $this->config['blocked_src']) {
                return $this->config['blocked_src'];
            }
        }
        else if (preg_match('/^data:image.+/i', $uri)) { // RFC2397
            return $uri;
        }
    }

    /**
     * Check it the tag/attribute may contain an URI
     */
    private function is_link_attribute($tag, $attr)
    {
        return ($tag == 'a' || $tag == 'area') && $attr == 'href';
    }

    /**
     * Check it the tag/attribute may contain an image URI
     */
    private function is_image_attribute($tag, $attr)
    {
        return $attr == 'background'
            || $attr == 'color-profile' // SVG
            || ($attr == 'poster' && $tag == 'video')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -390,7 +390,30 @@
                 return $this->config['blocked_src'];
             }
         }
-        else if (preg_match('/^data:image.+/i', $uri)) { // RFC2397
+        else if (preg_match('/^data:image\/([^,]+),(.+)$/i', $uri, $matches)) { // RFC2397
+            // svg images can be insecure, we'll sanitize them
+            if (stripos($matches[1], 'svg') !== false) {
+                $svg = $matches[2];
+
+                if (stripos($matches[1], ';base64') !== false) {
+                    $svg  = base64_decode($svg);
+                    $type = $matches[1];
+                }
+                else {
+                    $type = $matches[1] . ';base64';
+                }
+
+                $washer = new self($this->config);
+                $svg    = $washer->wash($svg);
+
+                // Invalid svg content
+                if (empty($svg)) {
+                    return null;
+                }
+
+                return 'data:image/' . $type . ',' . base64_encode($svg);
+            }
+
             return $uri;
         }
     }
@@ -400,7 +423,7 @@
      */
     private function is_link_attribute($tag, $attr)
     {
-        return ($tag == 'a' || $tag == 'area') && $attr == 'href';
+        return $attr === 'href';
     }
 
     /**
@@ -412,6 +435,7 @@
             || $attr == 'color-profile' // SVG
             || ($attr == 'poster' && $tag == 'video')
             || ($attr == 'src' && preg_match('/^(img|image|source|input|video|audio)$/i', $tag))
+            || ($tag == 'use' && $attr == 'href') // SVG
             || ($tag == 'image' && $attr == 'href'); // SVG
     }
 
@@ -422,6 +446,31 @@
     {
         return in_array($attr, array('fill', 'filter', 'stroke', 'marker-start',
             'marker-end', 'marker-mid', 'clip-path', 'mask', 'cursor'));
+    }
+
+    /**
+     * Check if a specified element has an attribute with specified value.
+     * Do it in case-insensitive manner.
+     *
+     * @param DOMElement $node       The element
+     * @param string     $attr_name  The attribute name
+     * @param string     $attr_value The attribute value to find
+     *
+     * @return bool True if the specified attribute exists and has the expected value
+     */
+    private static function attribute_value($node, $attr_name, $attr_value)
+    {
+        $attr_name = strtolower($attr_name);
+
+        foreach ($node->attributes as $name => $attr) {
+            if (strtolower($name) === $attr_name) {
+                if (strtolower($attr_value) === strtolower($attr->nodeValue)) {
+                    return true;
+                }
+            }
+        }
+
+        return false;
     }
 
     /**
@@ -458,6 +507,15 @@
             switch ($node->nodeType) {
             case XML_ELEMENT_NODE: //Check element
                 $tagName = strtolower($node->nodeName);
+
+                if (in_array($tagName, array('animate', 'animatecolor', 'set', 'animatetransform'))
+                    && self::attribute_value($node, 'attributename', 'href')
+                ) {
+                    // Insecure svg tags
+                    $dump .= "<!-- $tagName blocked -->";
+                    break;
+                }
+
                 if ($callback = $this->handlers[$tagName]) {
                     $dump .= call_user_func($callback, $tagName,
                         $this->wash_attribs($node), $this->dumpHtml($node, $level), $this);
```
