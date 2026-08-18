# CrossVul Fix Pair: Files or Directories Accessible to External Parties in php
**Pair ID:** 4552_0
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4552_0`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```php
Lines 117-157 of the vulnerable file.

                    ));
                    $is_valid = false;
                }
            }
        }

        if (($hookReturn = Hook::exec('actionValidateCustomerAddressForm', array('form' => $this))) !== '') {
            $is_valid &= (bool) $hookReturn;
        }

        return $is_valid && parent::validate();
    }

    public function submit()
    {
        if (!$this->validate()) {
            return false;
        }

        $address = new Address(
            $this->getValue('id_address'),
            $this->language->id
        );

        foreach ($this->formFields as $formField) {
            $address->{$formField->getName()} = $formField->getValue();
        }

        if (!isset($this->formFields['id_state'])) {
            $address->id_state = 0;
        }

        if (empty($address->alias)) {
            $address->alias = $this->translator->trans('My Address', [], 'Shop.Theme.Checkout');
        }

        Hook::exec('actionSubmitCustomerAddressForm', array('address' => &$address));

        $this->setAddress($address);

        return $this->getPersister()->save(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,7 +134,7 @@
         }
 
         $address = new Address(
-            $this->getValue('id_address'),
+            Tools::getValue('id_address'),
             $this->language->id
         );
 
```
