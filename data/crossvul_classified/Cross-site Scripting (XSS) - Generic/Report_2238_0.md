# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2238_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2238_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 818-858 of the vulnerable file.

            // add attribute values
            foreach($row as $key=>$attvalue)
            {
                if(preg_match('/^a\d+$/', $key))
                {
                    $aRowToAdd['cell'][] = $attvalue;
                }
            }
            
            $aData->rows[] = $aRowToAdd;
        }

        echo ls_json_encode($aData);
    }

    /*
     * Fetches the attributes of a participant to be displayed in the attribute subgrid
     */
    function getAttribute_json()
    {
        $iParticipantId = Yii::app()->request->getQuery('pid');
        $records = ParticipantAttributeName::model()->getParticipantVisibleAttribute($iParticipantId);
        $records = subval_sort($records, "attribute_name", "asc");

        $i = 0;

        $doneattributes = array(); //If the user has any actual attribute values, they'll be stored here

        /* Iterate through each attribute owned by this user */
        foreach ($records as $row)
        {
            $outputs[$i] = array("", $row['participant_id']."_".$row['attribute_id'], $row['attribute_type'], $row['attribute_id'], $row['attribute_name'], $row['value']);
            /* Collect allowed values for a DropDown attribute */
            if ($row['attribute_type'] == "DD")
            {
                $attvalues = ParticipantAttributeName::model()->getAttributesValues($row['attribute_id']);
                if (!empty($attvalues))
                {
                    $attval = "";
                    foreach ($attvalues as $val)
                    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -835,7 +835,7 @@
      */
     function getAttribute_json()
     {
-        $iParticipantId = Yii::app()->request->getQuery('pid');
+        $iParticipantId = strip_tags(Yii::app()->request->getQuery('pid'));
         $records = ParticipantAttributeName::model()->getParticipantVisibleAttribute($iParticipantId);
         $records = subval_sort($records, "attribute_name", "asc");
 
```
