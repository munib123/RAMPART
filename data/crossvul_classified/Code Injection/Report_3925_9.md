# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 3925_9
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3925_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 876-916 of the vulnerable file.

   // delete search_config_global
   foreach ($DB->request("glpi_profilerights",
                         "`name` = 'search_config_global' AND `rights` = '".ALLSTANDARDRIGHT."'") as $profrights) {

      $query  = "UPDATE `glpi_profilerights`
                 SET `rights` = `rights` | " . DisplayPreference::GENERAL ."
                 WHERE `profiles_id` = '".$profrights['profiles_id']."'
                      AND `name` = 'search_config'";
      $DB->queryOrDie($query, "0.85 update search_config with search_config_global");
   }
   $query = "DELETE
             FROM `glpi_profilerights`
             WHERE `name` = 'search_config_global'";
   $DB->queryOrDie($query, "0.85 delete search_config_global right");

   // delete check_update
   foreach ($DB->request("glpi_profilerights",
                         "`name` = 'check_update' AND `rights` = '1'") as $profrights) {

      $query  = "UPDATE `glpi_profilerights`
                 SET `rights` = `rights` | " . Backup::CHECKUPDATE ."
                 WHERE `profiles_id` = '".$profrights['profiles_id']."'
                      AND `name` = 'backup'";
         $DB->queryOrDie($query, "0.85 update backup with check_update");
   }
   $query = "DELETE
             FROM `glpi_profilerights`
             WHERE `name` = 'check_update'";
   $DB->queryOrDie($query, "0.85 delete check_update right");

   // entity_dropdown => right by object

   // pour que la proc??dure soit r??-entrante et ne pas perdre les s??lections dans le profile
   if (countElementsInTable("glpi_profilerights", ['name' => 'domain']) == 0) {
      ProfileRight::addProfileRights(['domain']);
      ProfileRight::updateProfileRightsAsOtherRights('domain', 'entity_dropdown');
   }

   if (countElementsInTable("glpi_profilerights", ['name' => 'location']) == 0) {
      ProfileRight::addProfileRights(['location']);
      ProfileRight::updateProfileRightsAsOtherRights('location', 'entity_dropdown');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -893,7 +893,7 @@
                          "`name` = 'check_update' AND `rights` = '1'") as $profrights) {
 
       $query  = "UPDATE `glpi_profilerights`
-                 SET `rights` = `rights` | " . Backup::CHECKUPDATE ."
+                 SET `rights` = `rights` | " . 1024 /*Backup::CHECKUPDATE*/ ."
                  WHERE `profiles_id` = '".$profrights['profiles_id']."'
                       AND `name` = 'backup'";
          $DB->queryOrDie($query, "0.85 update backup with check_update");
```
