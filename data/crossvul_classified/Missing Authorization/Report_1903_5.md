# CrossVul Fix Pair: Missing Authorization in php
**Pair ID:** 1903_5
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1903_5`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 358-398 of the vulnerable file.

      }
      $CFG_GLPI['language'] = $config;
      $CFG_GLPI['default_language'] = $legacy_config;
      $result = \Session::getPreferredLanguage();

      if ($header_backup !== null) {
         $_SERVER['HTTP_ACCEPT_LANGUAGE'] = $header_backup;
      }
      $CFG_GLPI = $cfg_backup;

      $this->string($result)->isEqualTo($expected);
   }


   protected function idorProvider() {
      return [
         ['itemtype' => 'Computer'],
         ['itemtype' => 'Ticket'],
         ['itemtype' => 'Glpi\\Dashboard\\Item'],
         ['itemtype' => 'User', 'add_params' => ['right' => 'all']],
      ];
   }

   /**
    * @dataProvider idorProvider
    */
   function testIDORToken(string $itemtype = "", array $add_params = []) {
      // generate token
      $token = \Session::getNewIDORToken($itemtype, $add_params);
      $this->string($token)->hasLength(64);

      // token exists in session and is valid
      $this->array($_SESSION['glpiidortokens'][$token])
         ->string['itemtype']->isEqualTo($itemtype)
         ->string['expires'];

      if (count($add_params) > 0) {
         $this->array($_SESSION['glpiidortokens'][$token])->size->isEqualTo(2 + count($add_params));
      }

      // validate token with dedicated method
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -375,6 +375,7 @@
          ['itemtype' => 'Ticket'],
          ['itemtype' => 'Glpi\\Dashboard\\Item'],
          ['itemtype' => 'User', 'add_params' => ['right' => 'all']],
+         ['itemtype' => 'User', 'add_params' => ['entity_restrict' => 0]],
       ];
    }
 
```
