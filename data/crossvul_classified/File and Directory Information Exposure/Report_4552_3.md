# CrossVul Fix Pair: Files or Directories Accessible to External Parties in php
**Pair ID:** 4552_3
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4552_3`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```php
Lines 73-116 of the vulnerable file.

        return $this;
    }

    public function setAskForNewPassword($ask_for_new_password)
    {
        $this->ask_for_new_password = $ask_for_new_password;

        return $this;
    }

    public function setPasswordRequired($password_is_required)
    {
        $this->password_is_required = $password_is_required;

        return $this;
    }

    public function getFormat()
    {
        $format = [];

        $format['id_customer'] = (new FormField())
            ->setName('id_customer')
            ->setType('hidden');

        $genders = Gender::getGenders($this->language->id);
        if ($genders->count() > 0) {
            $genderField = (new FormField())
                ->setName('id_gender')
                ->setType('radio-buttons')
                ->setLabel(
                    $this->translator->trans(
                        'Social title',
                        [],
                        'Shop.Forms.Labels'
                    )
                );
            foreach ($genders as $gender) {
                $genderField->addAvailableValue($gender->id, $gender->name);
            }
            $format[$genderField->getName()] = $genderField;
        }

        $format['firstname'] = (new FormField())
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,10 +91,6 @@
     {
         $format = [];
 
-        $format['id_customer'] = (new FormField())
-            ->setName('id_customer')
-            ->setType('hidden');
-
         $genders = Gender::getGenders($this->language->id);
         if ($genders->count() > 0) {
             $genderField = (new FormField())
```
