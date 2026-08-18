# CrossVul Fix Pair: Use of Hard-coded Credentials in php
**Pair ID:** 4550_1
**Vulnerability Class:** Use of Hard-coded Credentials
**CWE:** CWE-798
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4550_1`)

## Vulnerability Information & PoC

## Description
Use of Hard-coded Credentials - Hard-coded credentials typically create a significant hole that allows an attacker to bypass the authentication that has been configured by the product administrator.

## Vulnerable Code
```php
Lines 41-77 of the vulnerable file.


$mailcollector = new MailCollector;

if (isset($_REQUEST['action'])) {
   switch ($_REQUEST['action']) {
      case "getFoldersList":
         // Load config if already exists
         // Necessary if password is not updated
         if (array_key_exists('id', $_REQUEST)) {
            $mailcollector->getFromDB($_REQUEST['id']);
         }

         // Update fields with input values
         $input = $_REQUEST;
         $input['login'] = stripslashes($input['login']);

         if (isset($input["passwd"])) {
            if (empty($input["passwd"])) {
               unset($input["passwd"]);
            } else {
               $input["passwd"] = Toolbox::encrypt(stripslashes($input["passwd"]), GLPIKEY);
            }
         }

         if (isset($input['mail_server']) && !empty($input['mail_server'])) {
            $input["host"] = Toolbox::constructMailServerConfig($input);
         }

         if (!isset($input['errors'])) {
            $input['errors'] = 0;
         }

         $mailcollector->fields = array_merge($mailcollector->fields, $input);
         echo $mailcollector->displayFoldersList($_REQUEST['input_id']);
         break;
   }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,7 +58,7 @@
             if (empty($input["passwd"])) {
                unset($input["passwd"]);
             } else {
-               $input["passwd"] = Toolbox::encrypt(stripslashes($input["passwd"]), GLPIKEY);
+               $input["passwd"] = Toolbox::encrypt(stripslashes($input["passwd"]));
             }
          }
 
```
