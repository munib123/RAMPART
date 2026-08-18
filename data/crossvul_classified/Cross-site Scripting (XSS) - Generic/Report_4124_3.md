# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4124_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4124_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 98-138 of the vulnerable file.

                    $product_name = '';
                    if (Validate::isLoadedObject($product) && isset($product->name[(int) $this->context->language->id])) {
                        $product_name = $product->name[(int) $this->context->language->id];
                    }

                    if (Validate::isLoadedObject($customer)) {
                        Mail::Send(
                            $this->context->language->id,
                            'order_customer_comment',
                            $this->trans(
                                'Message from a customer',
                                array(),
                                'Emails.Subject'
                            ),
                            array(
                                '{lastname}' => $customer->lastname,
                                '{firstname}' => $customer->firstname,
                                '{email}' => $customer->email,
                                '{id_order}' => (int) $order->id,
                                '{order_name}' => $order->getUniqReference(),
                                '{message}' => Tools::nl2br($msgText),
                                '{product_name}' => $product_name,
                            ),
                            $to,
                            $toName,
                            (string) Configuration::get('PS_SHOP_EMAIL'),
                            $customer->firstname . ' ' . $customer->lastname,
                            null,
                            null,
                            _PS_MAIL_DIR_,
                            false,
                            null,
                            null,
                            $customer->email
                        );
                    }

                    Tools::redirect('index.php?controller=order-detail&id_order=' . $idOrder . '&messagesent');
                } else {
                    $this->redirect_after = '404';
                    $this->redirect();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,7 +115,7 @@
                                 '{email}' => $customer->email,
                                 '{id_order}' => (int) $order->id,
                                 '{order_name}' => $order->getUniqReference(),
-                                '{message}' => Tools::nl2br($msgText),
+                                '{message}' => Tools::nl2br(Tools::htmlentitiesUTF8($msgText)),
                                 '{product_name}' => $product_name,
                             ),
                             $to,
```
