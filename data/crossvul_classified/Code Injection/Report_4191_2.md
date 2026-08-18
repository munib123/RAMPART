# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 4191_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4191_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 201-241 of the vulnerable file.

        print ',"'.$val.'"';
      }
      if ($bean->getAttribute('chunits')) print ',"'.$subtotal['units'].'"';
      if ($bean->getAttribute('chcost')) {
        if ($user->can('manage_invoices') || $user->isClient())
          print ',"'.$subtotal['cost'].'"';
        else
          print ',"'.$subtotal['expenses'].'"';
      }
      print "\n";
    }
  } else {
    // Normal report. Print headers.
    print '"'.$i18n->get('label.date').'"';
    if ($user->can('view_reports') || $user->can('view_all_reports') || $user->isClient()) print ',"'.$i18n->get('label.user').'"';
    // User custom field labels.
    if ($custom_fields && $custom_fields->userFields) {
      foreach ($custom_fields->userFields as $userField) {
        $field_name = 'user_field_'.$userField['id'];
        $checkbox_control_name = 'show_'.$field_name;
        if ($bean->getAttribute($checkbox_control_name)) print ',"'.str_replace('"','""',$userField['label']).'"';
      }
    }
    if ($bean->getAttribute('chclient')) print ',"'.$i18n->get('label.client').'"';
    if ($bean->getAttribute('chproject')) print ',"'.$i18n->get('label.project').'"';
    if ($bean->getAttribute('chtask')) print ',"'.$i18n->get('label.task').'"';
    // Time custom field labels.
    if ($custom_fields && $custom_fields->timeFields) {
      foreach ($custom_fields->timeFields as $timeField) {
        $field_name = 'time_field_'.$timeField['id'];
        $checkbox_control_name = 'show_'.$field_name;
        if ($bean->getAttribute($checkbox_control_name)) print ',"'.str_replace('"','""',$timeField['label']).'"';
      }
    }
    if ($bean->getAttribute('chstart')) print ',"'.$i18n->get('label.start').'"';
    if ($bean->getAttribute('chfinish')) print ',"'.$i18n->get('label.finish').'"';
    if ($bean->getAttribute('chduration')) print ',"'.$i18n->get('label.duration').'"';
    if ($bean->getAttribute('chunits')) print ',"'.$i18n->get('label.work_units_short').'"';
    if ($bean->getAttribute('chnote')) print ',"'.$i18n->get('label.note').'"';
    if ($bean->getAttribute('chcost')) print ',"'.$i18n->get('label.cost').'"';
    if ($bean->getAttribute('chapproved')) print ',"'.$i18n->get('label.approved').'"';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -218,7 +218,7 @@
       foreach ($custom_fields->userFields as $userField) {
         $field_name = 'user_field_'.$userField['id'];
         $checkbox_control_name = 'show_'.$field_name;
-        if ($bean->getAttribute($checkbox_control_name)) print ',"'.str_replace('"','""',$userField['label']).'"';
+        if ($bean->getAttribute($checkbox_control_name)) print ',"'.ttNeutralizeForCsv($userField['label']).'"';
       }
     }
     if ($bean->getAttribute('chclient')) print ',"'.$i18n->get('label.client').'"';
@@ -229,7 +229,7 @@
       foreach ($custom_fields->timeFields as $timeField) {
         $field_name = 'time_field_'.$timeField['id'];
         $checkbox_control_name = 'show_'.$field_name;
-        if ($bean->getAttribute($checkbox_control_name)) print ',"'.str_replace('"','""',$timeField['label']).'"';
+        if ($bean->getAttribute($checkbox_control_name)) print ',"'.ttNeutralizeForCsv($timeField['label']).'"';
       }
     }
     if ($bean->getAttribute('chstart')) print ',"'.$i18n->get('label.start').'"';
@@ -248,24 +248,24 @@
     // Print items.
     foreach ($items as $item) {
       print '"'.$item['date'].'"';
-      if ($user->can('view_reports') || $user->can('view_all_reports') || $user->isClient()) print ',"'.str_replace('"','""',$item['user']).'"';
+      if ($user->can('view_reports') || $user->can('view_all_reports') || $user->isClient()) print ',"'.ttNeutralizeForCsv($item['user']).'"';
       // User custom fields.
       if ($custom_fields && $custom_fields->userFields) {
         foreach ($custom_fields->userFields as $userField) {
           $field_name = 'user_field_'.$userField['id'];
           $checkbox_control_name = 'show_'.$field_name;
-          if ($bean->getAttribute($checkbox_control_name)) print ',"'.str_replace('"','""',$item[$field_name]).'"';
-        }
-      }
-      if ($bean->getAttribute('chclient')) print ',"'.str_replace('"','""',$item['client']).'"';
-      if ($bean->getAttribute('chproject')) print ',"'.str_replace('"','""',$item['project']).'"';
-      if ($bean->getAttribute('chtask')) print ',"'.str_replace('"','""',$item['task']).'"';
+          if ($bean->getAttribute($checkbox_control_name)) print ',"'.ttNeutralizeForCsv($item[$field_name]).'"';
+        }
+      }
+      if ($bean->getAttribute('chclient')) print ',"'.ttNeutralizeForCsv($item['client']).'"';
+      if ($bean->getAttribute('chproject')) print ',"'.ttNeutralizeForCsv($item['project']).'"';
+      if ($bean->getAttribute('chtask')) print ',"'.ttNeutralizeForCsv($item['task']).'"';
       // Time custom fields.
       if ($custom_fields && $custom_fields->timeFields) {
         foreach ($custom_fields->timeFields as $timeField) {
           $field_name = 'time_field_'.$timeField['id'];
           $checkbox_control_name = 'show_'.$field_name;
-          if ($bean->getAttribute($checkbox_control_name)) print ',"'.str_replace('"','""',$item[$field_name]).'"';
+          if ($bean->getAttribute($checkbox_control_name)) print ',"'.ttNeutralizeForCsv($item[$field_name]).'"';
         }
       }
       if ($bean->getAttribute('chstart')) print ',"'.$item['start'].'"';
@@ -277,7 +277,7 @@
         print ',"'.$val.'"';
       }
       if ($bean->getAttribute('chunits')) print ',"'.$item['units'].'"';
-      if ($bean->getAttribute('chnote')) print ',"'.str_replace('"','""',$item['note']).'"';
+      if ($bean->getAttribute('chnote')) print ',"'.ttNeutralizeForCsv($item['note']).'"';
       if ($bean->getAttribute('chcost')) {
         if ($user->can('manage_invoices') || $user->isClient())
           print ',"'.$item['cost'].'"';
@@ -290,8 +290,8 @@
         $ip = $item['modified'] ? $item['modified_ip'].' '.$item['modified'] : $item['created_ip'].' '.$item['created'];
         print ',"'.$ip.'"';
       }
-      if ($bean->getAttribute('chinvoice')) print ',"'.str_replace('"','""',$item['invoice']).'"';
-      if ($bean->getAttribute('chtimesheet')) print ',"'.str_replace('"','""',$item['timesheet_name']).'"';
+      if ($bean->getAttribute('chinvoice')) print ',"'.ttNeutralizeForCsv($item['invoice']).'"';
+      if ($bean->getAttribute('chtimesheet')) print ',"'.ttNeutralizeForCsv($item['timesheet_name']).'"';
       print "\n";
     }
   }
```
