# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5393_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5393_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 154-194 of the vulnerable file.

        if ($this->params['id'] != "default") {
            $active = self::getEditorSettings($this->params['id'], $this->params['editor']);
            $active->active = 1;
            $db->updateObject($active, 'htmleditor_' . $this->params['editor'], null, 'id');
        }
        expHistory::returnTo('manageable');
    }

    function preview()
    {
        if ($this->params['id'] == 0) { // we want the default editor
            $demo = new stdClass();
            $demo->id = 0;
            $demo->name = "Default";
            if ($this->params['editor'] == 'ckeditor') {
                $demo->skin = 'kama';
            } elseif ($this->params['editor'] == 'tinymce') {
                $demo->skin = 'lightgray';
            }
        } else {
            $demo = self::getEditorSettings($this->params['id'], $this->params['editor']);
        }
        assign_to_template(
            array(
                'demo' => $demo,
                'editor' => $this->params['editor']
            )
        );
    }

    public static function getEditorSettings($settings_id, $editor)
    {
        global $db;

        return @$db->selectObject('htmleditor_' . $editor, "id=" . $settings_id);
    }

    public static function getActiveEditorSettings($editor)
    {
        global $db;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,7 +171,7 @@
                 $demo->skin = 'lightgray';
             }
         } else {
-            $demo = self::getEditorSettings($this->params['id'], $this->params['editor']);
+            $demo = self::getEditorSettings($this->params['id'], expString::escape($this->params['editor']));
         }
         assign_to_template(
             array(
```
