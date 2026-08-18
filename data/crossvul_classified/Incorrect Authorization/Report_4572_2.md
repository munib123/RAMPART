# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 523-563 of the vulnerable file.

                    $search_result = array_search($template, $theme_templates);
                    $array[$iso_code][] = array(
                        'id' => substr($template, 0, -5),
                        'name' => substr($template, 0, -5),
                        'folder' => ((!empty($search_result) ? $theme_path : $default_path)),
                    );
                }
            }
        }

        return $array;
    }

    public function postProcess()
    {
        if (Tools::isSubmit($this->table . 'Orderby') || Tools::isSubmit($this->table . 'Orderway')) {
            $this->filter = true;
        }

        if (Tools::isSubmit('submitAddorder_return_state')) {
            $id_order_return_state = Tools::getValue('id_order_return_state');

            // Create Object OrderReturnState
            $order_return_state = new OrderReturnState((int) $id_order_return_state);

            $order_return_state->color = Tools::getValue('color');
            $order_return_state->name = array();
            foreach (Language::getIDs(false) as $id_lang) {
                $order_return_state->name[$id_lang] = Tools::getValue('name_' . $id_lang);
            }

            // Update object
            if (!$order_return_state->save()) {
                $this->errors[] = $this->trans('An error has occurred: Can\'t save the current order\'s return status.', array(), 'Admin.Orderscustomers.Notification');
            } else {
                Tools::redirectAdmin(self::$currentIndex . '&conf=4&token=' . $this->token);
            }
        }

        if (Tools::isSubmit('submitBulkdeleteorder_return_state')) {
            $this->className = 'OrderReturnState';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -540,6 +540,10 @@
         }
 
         if (Tools::isSubmit('submitAddorder_return_state')) {
+            if (!$this->access('add')) {
+                return;
+            }
+
             $id_order_return_state = Tools::getValue('id_order_return_state');
 
             // Create Object OrderReturnState
@@ -560,6 +564,10 @@
         }
 
         if (Tools::isSubmit('submitBulkdeleteorder_return_state')) {
+            if (!$this->access('delete')) {
+                return;
+            }
+
             $this->className = 'OrderReturnState';
             $this->table = 'order_return_state';
             $this->boxes = Tools::getValue('order_return_stateBox');
@@ -567,6 +575,10 @@
         }
 
         if (Tools::isSubmit('deleteorder_return_state')) {
+            if (!$this->access('delete')) {
+                return;
+            }
+
             $id_order_return_state = Tools::getValue('id_order_return_state');
 
             // Create Object OrderReturnState
@@ -580,6 +592,10 @@
         }
 
         if (Tools::isSubmit('submitAdd' . $this->table)) {
+            if (!$this->access('add')) {
+                return;
+            }
+
             $this->deleted = false; // Disabling saving historisation
             $_POST['invoice'] = (int) Tools::getValue('invoice_on');
             $_POST['logable'] = (int) Tools::getValue('logable_on');
@@ -598,6 +614,10 @@
 
             return parent::postProcess();
         } elseif (Tools::isSubmit('delete' . $this->table)) {
+            if (!$this->access('delete')) {
+                return;
+            }
+
             $order_state = new OrderState(Tools::getValue('id_order_state'), $this->context->language->id);
             if (!$order_state->isRemovable()) {
                 $this->errors[] = $this->trans('For security reasons, you cannot delete default order statuses.', array(), 'Admin.Shopparameters.Notification');
@@ -605,6 +625,10 @@
                 return parent::postProcess();
             }
         } elseif (Tools::isSubmit('submitBulkdelete' . $this->table)) {
+            if (!$this->access('delete')) {
+                return;
+            }
+
             foreach (Tools::getValue($this->table . 'Box') as $selection) {
                 $order_state = new OrderState((int) $selection, $this->context->language->id);
                 if (!$order_state->isRemovable()) {
```
