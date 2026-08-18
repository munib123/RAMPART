# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4238_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4238_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 395-435 of the vulnerable file.


        // allow url(#id) used in SVG
        if ($uri[0] == '#') {
            if ($this->_css_prefix !== null) {
                $uri = '#' . $this->_css_prefix . substr($uri, 1);
            }

            return $uri;
        }

        if (preg_match('/^(http|https|ftp):.+/i', $uri)) {
            if ($this->config['allow_remote']) {
                return $uri;
            }

            $this->extlinks = true;
            if ($is_image && $blocked_source && $this->config['blocked_src']) {
                return $this->config['blocked_src'];
            }
        }
        else if ($is_image && preg_match('/^data:image.+/i', $uri)) { // RFC2397
            return $uri;
        }
    }

    /**
     * Wash Href value
     *
     * @param string $href Href attribute value (link)
     *
     * @return string Washed href
     */
    private function wash_link($href)
    {
        if (strlen($href) && !preg_match('!^(javascript|vbscript|data:)!i', $href)) {
            if ($href[0] == '#' && $this->_css_prefix !== null) {
                return '#' . $this->_css_prefix . substr($href, 1);
            }

            if (preg_match('!^[a-zA-Z._-]+$!', $href)) {
                return 'http://' . $href;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -412,7 +412,30 @@
                 return $this->config['blocked_src'];
             }
         }
-        else if ($is_image && preg_match('/^data:image.+/i', $uri)) { // RFC2397
+        else if ($is_image && preg_match('/^data:image\/([^,]+),(.+)$/i', $uri, $matches)) { // RFC2397
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
@@ -451,7 +474,7 @@
      */
     private function is_link_attribute($tag, $attr)
     {
-        return ($tag == 'a' || $tag == 'area') && $attr == 'href';
+        return $attr === 'href';
     }
 
     /**
@@ -468,6 +491,7 @@
             || $attr == 'color-profile' // SVG
             || ($attr == 'poster' && $tag == 'video')
             || ($attr == 'src' && preg_match('/^(img|image|source|input|video|audio)$/i', $tag))
+            || ($tag == 'use' && $attr == 'href') // SVG
             || ($tag == 'image' && $attr == 'href'); // SVG
     }
 
@@ -483,6 +507,31 @@
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
@@ -531,6 +580,13 @@
                     }
 
                     $node->setAttribute('href', (string) $uri);
+                }
+                else if (in_array($tagName, array('animate', 'animatecolor', 'set', 'animatetransform'))
+                    && self::attribute_value($node, 'attributename', 'href')
+                ) {
+                    // Insecure svg tags
+                    $dump .= "<!-- $tagName blocked -->";
+                    break;
                 }
 
                 if ($callback = $this->handlers[$tagName]) {
```
