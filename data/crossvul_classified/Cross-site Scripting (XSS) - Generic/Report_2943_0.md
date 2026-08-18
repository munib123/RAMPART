# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2943_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2943_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 204-238 of the vulnerable file.

        } else {
            $row['link'] = '<span class="horde-resource-none">'
                . $label . '</span>';
        }

        if ($boxrow) {
            $this->containers[$container]['type'] = $row['type'];
            if (!isset($row['style'])) {
                $row['style'] = '';
            }
            if (!isset($row['color'])) {
                $row['color'] = '#dddddd';
            }
            $foreground = '000';
            if (Horde_Image::brightness($row['color']) < 128) {
                $foreground = 'fff';
            }
            if (strlen($row['style'])) {
                $row['style'] .= ';';
            }
            $row['style'] .= 'background-color:' . $row['color']
                . ';color:#' . $foreground;
            if (isset($row['edit'])) {
                $row['editLink'] = $row['edit']
                    ->link(array(
                        'title' =>  _("Edit"),
                        'class' => 'horde-resource-edit-' . $foreground))
                    . '&#9658;' . '</a>';
            }
        }

        $this->containers[$container]['rows'][] = $row;
    }

}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -221,7 +221,7 @@
             if (strlen($row['style'])) {
                 $row['style'] .= ';';
             }
-            $row['style'] .= 'background-color:' . $row['color']
+            $row['style'] .= 'background-color:' . htmlspecialchars($row['color'])
                 . ';color:#' . $foreground;
             if (isset($row['edit'])) {
                 $row['editLink'] = $row['edit']
```
