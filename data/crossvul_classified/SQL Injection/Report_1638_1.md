# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1638_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1638_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 42-83 of the vulnerable file.

        $importlanguages[]=(string)$language;
    }

    if (!in_array($sBaseLanguage,$importlanguages))
    {
        $results['fatalerror'] = gT("The languages of the imported group file must at least include the base language of this survey.");
        return $results;
    }
    // First get an overview of fieldnames - it's not useful for the moment but might be with newer versions
    /*
    $fieldnames=array();
    foreach ($xml->questions->fields->fieldname as $fieldname )
    {
    $fieldnames[]=(string)$fieldname;
    };*/


    // Import group table ===================================================================================


    $query = "SELECT MAX(group_order) AS maxgo FROM {{groups}} WHERE sid=$iNewSID";
    $iGroupOrder = Yii::app()->db->createCommand($query)->queryScalar();
    if ($iGroupOrder === false)
    {
        $iNewGroupOrder=0;
    }
    else
    {
        $iNewGroupOrder=$iGroupOrder+1;
    }

    foreach ($xml->groups->rows->row as $row)
    {
        $insertdata=array();
        foreach ($row as $key=>$value)
        {
            $insertdata[(string)$key]=(string)$value;
        }
        $iOldSID=$insertdata['sid'];
        $insertdata['sid']=$iNewSID;
        $insertdata['group_order']=$iNewGroupOrder;
        $oldgid=$insertdata['gid']; unset($insertdata['gid']); // save the old qid
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,8 +59,7 @@
     // Import group table ===================================================================================
 
 
-    $query = "SELECT MAX(group_order) AS maxgo FROM {{groups}} WHERE sid=$iNewSID";
-    $iGroupOrder = Yii::app()->db->createCommand($query)->queryScalar();
+    $iGroupOrder = Yii::app()->db->createCommand()->select('MAX(group_order)')->from('{{groups}}')->where('sid=:sid',array(':sid'=>$iNewSID))->queryScalar();
     if ($iGroupOrder === false)
     {
         $iNewGroupOrder=0;
```
