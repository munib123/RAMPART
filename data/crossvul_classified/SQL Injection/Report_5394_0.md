# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5394_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5394_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 45-85 of the vulnerable file.

    static function author()
    {
        return "Phillip Ball";
    }

    static function hasSources()
    {
        return false;
    }

    static function hasContent()
    {
        return false;
    }

    function __construct($src = null, $params = array())
    {
        parent:: __construct($src, $params);
        if (empty($this->params['editor'])) {
            $this->params['editor'] = SITE_WYSIWYG_EDITOR;
        }
    }

    function manage()
    {
        global $db;

        expHistory::set('manageable', $this->params);
        if (SITE_WYSIWYG_EDITOR == "FCKeditor") {
            flash('error', gt('FCKeditor is deprecated!'));
            redirect_to(array("module" => "administration", "action" => "configure_site"));
        }

        // otherwise, on to the show
        $configs = $db->selectObjects('htmleditor_' . $this->params['editor'], 1);

        assign_to_template(
            array(
                'configs' => $configs,
                'editor' => $this->params['editor']
            )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,6 +62,8 @@
         parent:: __construct($src, $params);
         if (empty($this->params['editor'])) {
             $this->params['editor'] = SITE_WYSIWYG_EDITOR;
+        } else {
+            $this->params['editor'] = preg_replace("/[^[:alnum:][:space:]]/u", '', $this->params['editor']);
         }
     }
 
@@ -171,7 +173,7 @@
                 $demo->skin = 'lightgray';
             }
         } else {
-            $demo = self::getEditorSettings($this->params['id'], expString::escape($this->params['editor']));
+            $demo = self::getEditorSettings($this->params['id'], $this->params['editor']);
         }
         assign_to_template(
             array(
```
