# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4135_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4135_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 300-340 of the vulnerable file.

                $notifications['messages'] = $this->context->controller->success;
                $notifications['nw_error'] = false;
            }
        } elseif (empty($this->context->cookie->contactFormToken)
            || empty($this->context->cookie->contactFormTokenTTL)
            || $this->context->cookie->contactFormTokenTTL < time()
        ) {
            $this->createNewToken();
        }

        if (($id_customer_thread = (int)Tools::getValue('id_customer_thread'))
            && $token = Tools::getValue('token')
        ) {
            $cm = new CustomerThread($id_customer_thread);

            if ($cm->token == $token) {
                $this->customer_thread = $this->context->controller->objectPresenter->present($cm);
            }
        }
        $this->contact['contacts'] = $this->getTemplateVarContact();
        $this->contact['message'] = html_entity_decode(Tools::getValue('message'));
        $this->contact['allow_file_upload'] = (bool) Configuration::get('PS_CUSTOMER_SERVICE_FILE_UPLOAD');

        if (!(bool)Configuration::isCatalogMode()) {
            $this->contact['orders'] = $this->getTemplateVarOrders();
        } else {
            $this->contact['orders'] = [];
        }

        if (isset($this->customer_thread['email'])) {
            $this->contact['email'] = $this->customer_thread['email'];
        } else {
            $this->contact['email'] = Tools::safeOutput(
                Tools::getValue(
                    'from',
                    !empty($this->context->cookie->email) && Validate::isEmail($this->context->cookie->email) ?
                    $this->context->cookie->email :
                    ''
                )
            );
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -317,7 +317,7 @@
             }
         }
         $this->contact['contacts'] = $this->getTemplateVarContact();
-        $this->contact['message'] = html_entity_decode(Tools::getValue('message'));
+        $this->contact['message'] = Tools::getValue('message');
         $this->contact['allow_file_upload'] = (bool) Configuration::get('PS_CUSTOMER_SERVICE_FILE_UPLOAD');
 
         if (!(bool)Configuration::isCatalogMode()) {
@@ -388,9 +388,10 @@
     {
         $orders = [];
 
-        if (!isset($this->customer_thread['id_order'])
+        if (empty($this->customer_thread['id_order'])
             && isset($this->context->customer)
-            && $this->context->customer->isLogged()) {
+            && $this->context->customer->isLogged()
+        ) {
             $customer_orders = Order::getCustomerOrders($this->context->customer->id);
 
             foreach ($customer_orders as $customer_order) {
@@ -401,7 +402,7 @@
                     $orders[$customer_order['id_order']]['products'] = $myOrder->getProducts();
                 }
             }
-        } elseif (isset($this->customer_thread['id_order']) && (int)$this->customer_thread['id_order'] > 0) {
+        } elseif (isset($this->customer_thread['id_order']) && (int) $this->customer_thread['id_order'] > 0) {
             $myOrder = new Order($this->customer_thread['id_order']);
 
             if (Validate::isLoadedObject($myOrder)) {
@@ -411,13 +412,13 @@
             }
         }
 
-        if (isset($this->customer_thread['id_product'])) {
+        if (!empty($this->customer_thread['id_product'])) {
             $id_order = isset($this->customer_thread['id_order']) ?
-                      (int)$this->customer_thread['id_order'] :
+                      (int) $this->customer_thread['id_order'] :
                       0;
 
             $orders[$id_order]['products'][(int)$this->customer_thread['id_product']] = $this->context->controller->objectPresenter->present(
-                new Product((int)$this->customer_thread['id_product'])
+                new Product((int) $this->customer_thread['id_product'])
             );
         }
 
@@ -586,7 +587,7 @@
                     '{lastname}' => '',
                     '{order_name}' => '-',
                     '{attached_file}' => '-',
-                    '{message}' => Tools::nl2br(Tools::stripslashes($message)),
+                    '{message}' => Tools::nl2br(Tools::htmlentitiesUTF8(Tools::stripslashes($message))),
                     '{email}' =>  $from,
                     '{product_name}' => '',
                 ];
```
