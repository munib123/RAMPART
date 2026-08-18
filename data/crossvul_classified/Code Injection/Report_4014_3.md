# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 4014_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4014_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 111-151 of the vulnerable file.

     */
    public static function extractTextFromField($field): string
    {
        if (empty($field)) {
            return '';
        }
        if ($field instanceof MatrixBlockQuery
            || (\is_array($field) && $field[0] instanceof MatrixBlock)) {
            $result = self::extractTextFromMatrix($field);
        } elseif ($field instanceof NeoBlockQuery
            || (\is_array($field) && $field[0] instanceof NeoBlock)) {
            $result = self::extractTextFromNeo($field);
        } elseif ($field instanceof SuperTableBlockQuery
            || (\is_array($field) && $field[0] instanceof SuperTableBlock)) {
            $result = self::extractTextFromSuperTable($field);
        } elseif ($field instanceof TagQuery
            || (\is_array($field) && $field[0] instanceof Tag)) {
            $result = self::extractTextFromTags($field);
        } else {
            if (\is_array($field)) {
                $result = strip_tags((string)$field[0]);
            } else {
                $result = strip_tags((string)$field);
            }
        }

        return $result;
    }

    /**
     * Extract concatenated text from all of the tags in the $tagElement and
     * return as a comma-delimited string
     *
     * @param TagQuery|Tag[] $tags
     *
     * @return string
     */
    public static function extractTextFromTags($tags): string
    {
        if (empty($tags)) {
            return '';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -128,13 +128,28 @@
             $result = self::extractTextFromTags($field);
         } else {
             if (\is_array($field)) {
-                $result = strip_tags((string)$field[0]);
+                $result = self::smartStripTags((string)$field[0]);
             } else {
-                $result = strip_tags((string)$field);
-            }
-        }
-
-        return $result;
+                $result = self::smartStripTags((string)$field);
+            }
+        }
+
+        return $result;
+    }
+
+    /**
+     * Strip HTML tags, but replace them with a space rather than just eliminating them
+     *
+     * @param $str
+     * @return string
+     */
+    public static function smartStripTags($str)
+    {
+        $str = str_replace('<', ' <', $str);
+        $str = strip_tags($str);
+        $str = str_replace('  ', ' ', $str);
+
+        return $str;
     }
 
     /**
```
