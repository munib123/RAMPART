# CrossVul Fix Pair: Files or Directories Accessible to External Parties in php
**Pair ID:** 4552_2
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4552_2`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```php
Lines 59-99 of the vulnerable file.

    }

    public function setGuestAllowed($guest_allowed = true)
    {
        $this->formatter->setPasswordRequired(!$guest_allowed);
        $this->guest_allowed = $guest_allowed;

        return $this;
    }

    public function setPasswordRequired($passwordRequired)
    {
        $this->passwordRequired = $passwordRequired;

        return $this;
    }

    public function fillFromCustomer(Customer $customer)
    {
        $params = get_object_vars($customer);
        $params['id_customer'] = $customer->id;
        $params['birthday'] = $customer->birthday === '0000-00-00' ? null : Tools::displayDate($customer->birthday);

        return $this->fillWith($params);
    }

    /**
     * @return \Customer
     */
    public function getCustomer()
    {
        $customer = new Customer($this->getValue('id_customer'));

        foreach ($this->formFields as $field) {
            $customerField = $field->getName();
            if ($customerField === 'id_customer') {
                $customerField = 'id';
            }
            if (property_exists($customer, $customerField)) {
                $customer->$customerField = $field->getValue();
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,7 +76,6 @@
     public function fillFromCustomer(Customer $customer)
     {
         $params = get_object_vars($customer);
-        $params['id_customer'] = $customer->id;
         $params['birthday'] = $customer->birthday === '0000-00-00' ? null : Tools::displayDate($customer->birthday);
 
         return $this->fillWith($params);
@@ -87,13 +86,10 @@
      */
     public function getCustomer()
     {
-        $customer = new Customer($this->getValue('id_customer'));
+        $customer = new Customer($this->context->customer->id);
 
         foreach ($this->formFields as $field) {
             $customerField = $field->getName();
-            if ($customerField === 'id_customer') {
-                $customerField = 'id';
-            }
             if (property_exists($customer, $customerField)) {
                 $customer->$customerField = $field->getValue();
             }
@@ -119,10 +115,10 @@
         $birthdayField = $this->getField('birthday');
         if (!empty($birthdayField) &&
             !empty($birthdayField->getValue()) &&
-            Validate::isBirthDate($birthdayField->getValue(), Context::getContext()->language->date_format_lite)
+            Validate::isBirthDate($birthdayField->getValue(), $this->context->language->date_format_lite)
         ) {
             $dateBuilt = DateTime::createFromFormat(
-                Context::getContext()->language->date_format_lite,
+                $this->context->language->date_format_lite,
                 $birthdayField->getValue()
             );
             $birthdayField->setValue($dateBuilt->format('Y-m-d'));
```
