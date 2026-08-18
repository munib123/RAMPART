# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4575_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4575_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 41-75 of the vulnerable file.

     * {@inheritdoc}
     */
    public function handle(SearchCustomers $query)
    {
        $limit = 50;
        $phrases = array_unique($query->getPhrases());

        $customers = [];

        foreach ($phrases as $searchPhrase) {
            if (empty($searchPhrase)) {
                continue;
            }

            $customersResult = Customer::searchByName($searchPhrase, $limit);
            if (!is_array($customersResult)) {
                continue;
            }

            foreach ($customersResult as $customerArray) {
                if ($customerArray['active']) {
                    $customerArray['fullname_and_email'] = sprintf(
                        '%s %s - %s',
                        $customerArray['firstname'],
                        $customerArray['lastname'],
                        $customerArray['email']
                    );
                    $customers[$customerArray['id_customer']] = $customerArray;
                }
            }
        }

        return $customers;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,15 +58,26 @@
             }
 
             foreach ($customersResult as $customerArray) {
-                if ($customerArray['active']) {
-                    $customerArray['fullname_and_email'] = sprintf(
-                        '%s %s - %s',
-                        $customerArray['firstname'],
-                        $customerArray['lastname'],
-                        $customerArray['email']
-                    );
-                    $customers[$customerArray['id_customer']] = $customerArray;
+                if (!$customerArray['active']) {
+                    continue;
                 }
+
+                $customerArray['fullname_and_email'] = sprintf(
+                    '%s %s - %s',
+                    $customerArray['firstname'],
+                    $customerArray['lastname'],
+                    $customerArray['email']
+                );
+
+                unset(
+                    $customerArray['passwd'],
+                    $customerArray['secure_key'],
+                    $customerArray['last_passwd_gen'],
+                    $customerArray['reset_password_token'],
+                    $customerArray['reset_password_validity']
+                );
+                $customers[$customerArray['id_customer']] = $customerArray;
+
             }
         }
 
```
