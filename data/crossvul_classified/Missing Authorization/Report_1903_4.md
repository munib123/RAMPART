# CrossVul Fix Pair: Missing Authorization in php
**Pair ID:** 1903_4
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1903_4`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 748-788 of the vulnerable file.

      ];
   }

   /**
    * @dataProvider getDropdownValueProvider
    */
   public function testGetDropdownValue($params, $expected, $session_params = []) {
      $this->login();

      $bkp_params = [];
      //set session params if any
      if (count($session_params)) {
         foreach ($session_params as $param => $value) {
            if (isset($_SESSION[$param])) {
               $bkp_params[$param] = $_SESSION[$param];
            }
            $_SESSION[$param] = $value;
         }
      }

      $params['_idor_token'] = \Session::getNewIDORToken($params['itemtype'] ?? '');

      $result = \Dropdown::getDropdownValue($params, false);

      //reset session params before executing test
      if (count($session_params)) {
         foreach ($session_params as $param => $value) {
            if (isset($bkp_params[$param])) {
               $_SESSION[$param] = $bkp_params[$param];
            } else {
               unset($_SESSION[$param]);
            }
         }
      }

      $this->array($result)->isIdenticalTo($expected);
   }

   protected function getDropdownConnectProvider() {
      return [
         [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -765,7 +765,7 @@
          }
       }
 
-      $params['_idor_token'] = \Session::getNewIDORToken($params['itemtype'] ?? '');
+      $params['_idor_token'] = $this->generateIdor($params);
 
       $result = \Dropdown::getDropdownValue($params, false);
 
@@ -928,7 +928,7 @@
          }
       }
 
-      $params['_idor_token'] = \Session::getNewIDORToken($params['itemtype'] ?? '');
+      $params['_idor_token'] = $this->generateIdor($params);
 
       $result = \Dropdown::getDropdownConnect($params, false);
 
@@ -1331,4 +1331,12 @@
             ->hasSize(2);
 
    }
+
+   private function generateIdor(array $params = []) {
+      $idor_add_params = [];
+      if (isset($params['entity_restrict'])) {
+         $idor_add_params['entity_restrict'] = $params['entity_restrict'];
+      }
+      return \Session::getNewIDORToken(($params['itemtype'] ?? ''), $idor_add_params);
+   }
 }
```
