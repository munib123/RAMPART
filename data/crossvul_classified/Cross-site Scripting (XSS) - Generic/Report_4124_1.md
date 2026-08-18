# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4124_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4124_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 344-385 of the vulnerable file.

					LEFT OUTER JOIN ' . _DB_PREFIX_ . 'employee e
						ON e.id_employee = cm.id_employee
					LEFT OUTER JOIN ' . _DB_PREFIX_ . 'customer c
						ON (c.email = ct.email)
					WHERE ct.id_customer_thread = ' . (int) Tools::getValue('id_customer_thread') . '
					ORDER BY cm.date_add DESC
				');
                $output = $this->displayMessage($messages, true, (int) Tools::getValue('id_employee_forward'));
                $cm = new CustomerMessage();
                $cm->id_employee = (int) $this->context->employee->id;
                $cm->id_customer_thread = (int) Tools::getValue('id_customer_thread');
                $cm->ip_address = (int) ip2long(Tools::getRemoteAddr());
                $current_employee = $this->context->employee;
                $id_employee = (int) Tools::getValue('id_employee_forward');
                $employee = new Employee($id_employee);
                $email = Tools::getValue('email');
                $message = Tools::getValue('message_forward');
                if (($error = $cm->validateField('message', $message, null, array(), true)) !== true) {
                    $this->errors[] = $error;
                } elseif ($id_employee && $employee && Validate::isLoadedObject($employee)) {
                    $params = array(
                        '{messages}' => stripslashes($output),
                        '{employee}' => $current_employee->firstname . ' ' . $current_employee->lastname,
                        '{comment}' => stripslashes(Tools::nl2br($_POST['message_forward'])),
                        '{firstname}' => $employee->firstname,
                        '{lastname}' => $employee->lastname,
                    );

                    if (Mail::Send(
                        $this->context->language->id,
                        'forward_msg',
                        $this->trans(
                            'Fwd: Customer message',
                            array(),
                            'Emails.Subject',
                            $this->context->language->locale
                        ),
                        $params,
                        $employee->email,
                        $employee->firstname . ' ' . $employee->lastname,
                        $current_employee->email,
                        $current_employee->firstname . ' ' . $current_employee->lastname,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -361,13 +361,13 @@
                 if (($error = $cm->validateField('message', $message, null, array(), true)) !== true) {
                     $this->errors[] = $error;
                 } elseif ($id_employee && $employee && Validate::isLoadedObject($employee)) {
-                    $params = array(
-                        '{messages}' => stripslashes($output),
+                    $params = [
+                        '{messages}' => Tools::stripslashes($output),
                         '{employee}' => $current_employee->firstname . ' ' . $current_employee->lastname,
-                        '{comment}' => stripslashes(Tools::nl2br($_POST['message_forward'])),
+                        '{comment}' => Tools::stripslashes(Tools::nl2br($_POST['message_forward'])),
                         '{firstname}' => $employee->firstname,
                         '{lastname}' => $employee->lastname,
-                    );
+                    ];
 
                     if (Mail::Send(
                         $this->context->language->id,
@@ -393,13 +393,13 @@
                         $cm->add();
                     }
                 } elseif ($email && Validate::isEmail($email)) {
-                    $params = array(
-                        '{messages}' => Tools::nl2br(stripslashes($output)),
+                    $params = [
+                        '{messages}' => Tools::nl2br(Tools::stripslashes($output)),
                         '{employee}' => $current_employee->firstname . ' ' . $current_employee->lastname,
-                        '{comment}' => stripslashes($_POST['message_forward']),
+                        '{comment}' => Tools::stripslashes($_POST['message_forward']),
                         '{firstname}' => '',
                         '{lastname}' => '',
-                    );
+                    ];
 
                     if (Mail::Send(
                         $this->context->language->id,
@@ -449,15 +449,16 @@
                         $file_attachment['mime'] = $_FILES['joinFile']['type'];
                     }
                     $customer = new Customer($ct->id_customer);
-                    $params = array(
-                        '{reply}' => Tools::nl2br(Tools::getValue('reply_message')),
+
+                    $params = [
+                        '{reply}' => Tools::nl2br(Tools::htmlentitiesUTF8(Tools::getValue('reply_message'))),
                         '{link}' => Tools::url(
                             $this->context->link->getPageLink('contact', true, null, null, false, $ct->id_shop),
                             'id_customer_thread=' . (int) $ct->id . '&token=' . $ct->token
                         ),
                         '{firstname}' => $customer->firstname,
                         '{lastname}' => $customer->lastname,
-                    );
+                    ];
                     //#ct == id_customer_thread    #tc == token of thread   <== used in the synchronization imap
                     $contact = new Contact((int) $ct->id_contact, (int) $ct->id_lang);
 
@@ -894,32 +895,6 @@
         return parent::renderOptions();
     }
 
-    /**
-     * AdminController::getList() override.
-     *
-     * @see AdminController::getList()
-     *
-     * @param int $id_lang
-     * @param string|null $order_by
-     * @param string|null $order_way
-     * @param int $start
-     * @param int|null $limit
-     * @param int|bool $id_lang_shop
-     *
-     * @throws PrestaShopException
-     */
-    public function getList($id_lang, $order_by = null, $order_way = null, $start = 0, $limit = null, $id_lang_shop = false)
-    {
-        parent::getList($id_lang, $order_by, $order_way, $start, $limit, $id_lang_shop);
-
-        $nb_items = count($this->_list);
-        for ($i = 0; $i < $nb_items; ++$i) {
-            if (isset($this->_list[$i]['messages'])) {
-                $this->_list[$i]['messages'] = Tools::htmlentitiesDecodeUTF8($this->_list[$i]['messages']);
-            }
-        }
-    }
-
     public function updateOptionPsSavImapOpt($value)
     {
         if ($this->access('edit') != '1') {
```
