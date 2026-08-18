# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4567_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4567_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 374-414 of the vulnerable file.

            ),
            'submit' => array(
                'title' => $this->trans('Save', array(), 'Admin.Actions'),
            ),
        );

        $this->fields_value = array('alias' => $this->object->getAliases());

        return parent::renderForm();
    }

    public function processSave()
    {
        $search = (string) Tools::getValue('search');
        $string = (string) Tools::getValue('alias');
        $aliases = explode(',', $string);
        if (empty($search) || empty($string)) {
            $this->errors[] = $this->trans('Aliases and results are both required.', array(), 'Admin.Shopparameters.Notification');
        }
        if (!Validate::isValidSearch($search)) {
            $this->errors[] = $search . ' ' . $this->trans('Is not a valid result', array(), 'Admin.Shopparameters.Notification');
        }
        foreach ($aliases as $alias) {
            if (!Validate::isValidSearch($alias)) {
                $this->errors[] = $alias . ' ' . $this->trans('Is not a valid alias', array(), 'Admin.Shopparameters.Notification');
            }
        }

        if (!count($this->errors)) {
            foreach ($aliases as $alias) {
                $obj = new Alias(null, trim($alias), trim($search));
                $obj->save();
            }
        }

        if (empty($this->errors)) {
            $this->confirmations[] = $this->trans('Creation successful', array(), 'Admin.Shopparameters.Notification');
        }
    }

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -391,11 +391,11 @@
             $this->errors[] = $this->trans('Aliases and results are both required.', array(), 'Admin.Shopparameters.Notification');
         }
         if (!Validate::isValidSearch($search)) {
-            $this->errors[] = $search . ' ' . $this->trans('Is not a valid result', array(), 'Admin.Shopparameters.Notification');
+            $this->errors[] = Tools::safeOutput($search) . ' ' . $this->trans('Is not a valid result', array(), 'Admin.Shopparameters.Notification');
         }
         foreach ($aliases as $alias) {
             if (!Validate::isValidSearch($alias)) {
-                $this->errors[] = $alias . ' ' . $this->trans('Is not a valid alias', array(), 'Admin.Shopparameters.Notification');
+                $this->errors[] = Tools::safeOutput($alias) . ' ' . $this->trans('Is not a valid alias', array(), 'Admin.Shopparameters.Notification');
             }
         }
 
```
