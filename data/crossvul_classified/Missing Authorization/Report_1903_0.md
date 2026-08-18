# CrossVul Fix Pair: Missing Authorization in php
**Pair ID:** 1903_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1903_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 59-99 of the vulnerable file.

   $table = getTableForItemType($itemtype);

   $rand = mt_rand();
   if (isset($_POST["rand"])) {
      $rand = $_POST["rand"];
   }

   // Message for post-only
   if (!isset($_POST["admin"]) || ($_POST["admin"] == 0)) {
      echo "<br>".__('Enter the first letters (user, item name, serial or asset number)');
   }
   echo "<br>";
   $field_id = Html::cleanId("dropdown_".$_POST['myname'].$rand);
   $p = [
      'itemtype'            => $itemtype,
      'entity_restrict'     => $_POST['entity_restrict'],
      'table'               => $table,
      'multiple'            => $_POST["multiple"],
      'myname'              => $_POST["myname"],
      'rand'                => $_POST["rand"],
      '_idor_token'         => Session::getNewIDORToken($itemtype),
   ];

   if (isset($_POST["used"]) && !empty($_POST["used"])) {
      if (isset($_POST["used"][$itemtype])) {
         $p["used"] = $_POST["used"][$itemtype];
      }
   }

   // Add context if defined
   if (!empty($context)) {
      $p["context"] = $context;
   }

   echo Html::jsAjaxDropdown($_POST['myname'], $field_id,
                             $CFG_GLPI['root_doc']."/ajax/getDropdownFindNum.php",
                             $p);

   // Auto update summary of active or just solved tickets
   $params = ['items_id' => '__VALUE__',
                   'itemtype' => $_POST['itemtype']];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,7 +76,9 @@
       'multiple'            => $_POST["multiple"],
       'myname'              => $_POST["myname"],
       'rand'                => $_POST["rand"],
-      '_idor_token'         => Session::getNewIDORToken($itemtype),
+      '_idor_token'         => Session::getNewIDORToken($itemtype, [
+         'entity_restrict' => $_POST['entity_restrict'],
+      ]),
    ];
 
    if (isset($_POST["used"]) && !empty($_POST["used"])) {
```
