# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2239_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2239_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 746-788 of the vulnerable file.

        $this->csvExport($search,$aAttributes);
    }

    /**
     * Equal to getParticipants_json() but now with a search
     */
    function getParticipantsResults_json()
    {
        $searchcondition = Yii::app()->request->getpost('searchcondition');
        $finalcondition = array();
        $condition = explode("||", $searchcondition);
        $search = Participant::model()->getParticipantsSearchMultipleCondition($condition);
        return $this->getParticipants_json($search);
    }

    /*
       * Sends the data in JSON format extracted from the database to be displayed using the jqGrid
    */
    function getParticipants_json($search = null)
    {
        $page = Yii::app()->request->getPost('page');
        $limit = Yii::app()->request->getPost('rows');
        $limit = isset($limit) ? $limit : 50; //Stop division by zero errors

        $attid = ParticipantAttributeName::model()->getVisibleAttributes();
        $participantfields = array('participant_id', 'can_edit', 'firstname', 'lastname', 'email', 'blacklisted', 'survey', 'language', 'owner_uid');
        foreach ($attid as $key => $value)
        {
            array_push($participantfields, $value['attribute_id']);
        }
        $sidx = Yii::app()->request->getPost('sidx');
        $sidx = !empty($sidx) ? $sidx : "lastname";
        $sord = Yii::app()->request->getPost('sord');
        $sord = !empty($sord) ? $sord : "asc";
        $order = $sidx. " ". $sord;
        
        $aData = new stdClass;
        
        //If super admin all the participants will be visible
        if (Permission::model()->hasGlobalPermission('superadmin','read'))
        {
            $iUserID = null;
        } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -763,9 +763,9 @@
     */
     function getParticipants_json($search = null)
     {
-        $page = Yii::app()->request->getPost('page');
-        $limit = Yii::app()->request->getPost('rows');
-        $limit = isset($limit) ? $limit : 50; //Stop division by zero errors
+        $page = (int) Yii::app()->request->getPost('page');
+        $limit = (int) Yii::app()->request->getPost('rows');
+        $limit = empty($limit) ? $limit : 50; //Stop division by zero errors
 
         $attid = ParticipantAttributeName::model()->getVisibleAttributes();
         $participantfields = array('participant_id', 'can_edit', 'firstname', 'lastname', 'email', 'blacklisted', 'survey', 'language', 'owner_uid');
@@ -774,10 +774,11 @@
             array_push($participantfields, $value['attribute_id']);
         }
         $sidx = Yii::app()->request->getPost('sidx');
-        $sidx = !empty($sidx) ? $sidx : "lastname";
+        $sidx = in_array($sidx,$participantfields) ? $sidx : "lastname";
         $sord = Yii::app()->request->getPost('sord');
-        $sord = !empty($sord) ? $sord : "asc";
+        $sord = ($sord=='desc') ? 'desc' : 'asc';
         $order = $sidx. " ". $sord;
+                                                 
         
         $aData = new stdClass;
         
```
