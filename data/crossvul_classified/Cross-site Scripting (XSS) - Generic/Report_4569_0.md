# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4569_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4569_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 4064-4104 of the vulnerable file.

     * @return bool true if success
     */
    protected function processBulkDelete()
    {
        if (is_array($this->boxes) && !empty($this->boxes)) {
            $object = new $this->className();

            if (isset($object->noZeroObject)) {
                $objects_count = count(call_user_func(array($this->className, $object->noZeroObject)));

                // Check if all object will be deleted
                if ($objects_count <= 1 || count($this->boxes) == $objects_count) {
                    $this->errors[] = $this->trans('You need at least one object.', array(), 'Admin.Notifications.Error') .
                        ' <b>' . $this->table . '</b><br />' .
                        $this->trans('You cannot delete all of the items.', array(), 'Admin.Notifications.Error');
                }
            } else {
                $result = true;
                foreach ($this->boxes as $id) {
                    /** @var $to_delete ObjectModel */
                    $to_delete = new $this->className($id);
                    $delete_ok = true;
                    if ($this->deleted) {
                        $to_delete->deleted = 1;
                        if (!$to_delete->update()) {
                            $result = false;
                            $delete_ok = false;
                        }
                    } elseif (!$to_delete->delete()) {
                        $result = false;
                        $delete_ok = false;
                    }

                    if ($delete_ok) {
                        PrestaShopLogger::addLog(sprintf($this->l('%s deletion', 'AdminTab', false, false), $this->className), 1, null, $this->className, (int) $to_delete->id, true, (int) $this->context->employee->id);
                    } else {
                        $this->errors[] = $this->trans('Can\'t delete #%id%', array('%id%' => $id), 'Admin.Notifications.Error');
                    }
                }
                if ($result) {
                    $this->redirect_after = self::$currentIndex . '&conf=2&token=' . $this->token;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4081,7 +4081,7 @@
                 $result = true;
                 foreach ($this->boxes as $id) {
                     /** @var $to_delete ObjectModel */
-                    $to_delete = new $this->className($id);
+                    $to_delete = new $this->className((int) $id);
                     $delete_ok = true;
                     if ($this->deleted) {
                         $to_delete->deleted = 1;
@@ -4097,7 +4097,7 @@
                     if ($delete_ok) {
                         PrestaShopLogger::addLog(sprintf($this->l('%s deletion', 'AdminTab', false, false), $this->className), 1, null, $this->className, (int) $to_delete->id, true, (int) $this->context->employee->id);
                     } else {
-                        $this->errors[] = $this->trans('Can\'t delete #%id%', array('%id%' => $id), 'Admin.Notifications.Error');
+                        $this->errors[] = $this->trans('Can\'t delete #%id%', array('%id%' => (int) $id), 'Admin.Notifications.Error');
                     }
                 }
                 if ($result) {
```
