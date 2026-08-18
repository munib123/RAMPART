# CrossVul Fix Pair: Files or Directories Accessible to External Parties in php
**Pair ID:** 4552_1
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4552_1`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```php
Lines 49-94 of the vulnerable file.

        $this->country = $country;

        return $this;
    }

    public function getCountry()
    {
        return $this->country;
    }

    public function getFormat()
    {
        $fields = AddressFormat::getOrderedAddressFields(
            $this->country->id,
            true,
            true
        );
        $required = array_flip(AddressFormat::getFieldsRequired());

        $format = [
            'id_address' => (new FormField())
                ->setName('id_address')
                ->setType('hidden'),
            'id_customer' => (new FormField())
                ->setName('id_customer')
                ->setType('hidden'),
            'back' => (new FormField())
                ->setName('back')
                ->setType('hidden'),
            'token' => (new FormField())
                ->setName('token')
                ->setType('hidden'),
            'alias' => (new FormField())
                ->setName('alias')
                ->setLabel(
                    $this->getFieldLabel('alias')
                ),
        ];

        foreach ($fields as $field) {
            $formField = new FormField();
            $formField->setName($field);

            $fieldParts = explode(':', $field, 2);

            if (count($fieldParts) === 1) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -66,12 +66,6 @@
         $required = array_flip(AddressFormat::getFieldsRequired());
 
         $format = [
-            'id_address' => (new FormField())
-                ->setName('id_address')
-                ->setType('hidden'),
-            'id_customer' => (new FormField())
-                ->setName('id_customer')
-                ->setType('hidden'),
             'back' => (new FormField())
                 ->setName('back')
                 ->setType('hidden'),
```
