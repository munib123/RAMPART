# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5327_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5327_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 87-127 of the vulnerable file.

    function __construct($params = null, $get_assoc = true, $get_attached = true) {
        global $db;

        // @TODO Change this conditional check as the default value in argument list
        // if the params come thru as a null value we need to convert to an empty array
        if (empty($params)) {
            $params       = array();
            $get_assoc    = false;
            $get_attached = false;
        }

        // figure out the basic table info about this model
        $this->classinfo = new ReflectionClass($this);
        $this->classname = $this->classinfo->getName();
        $this->tablename = isset($this->table) ? $this->table : $this->classinfo->getName();

        $supports_revisions = $this->supports_revisions && ENABLE_WORKFLOW;
        $needs_approval = $this->needs_approval && ENABLE_WORKFLOW;

        // if the user passed in arguments to this constructor then we need to
        // retrieve objects 

        // If a number was sent in, we assume this is a DB record ID, so pull it
        if (!is_object($params) && !is_array($params)) {
            $where = '';
            if (is_numeric($params)) {
                $this->build($db->selectArray($this->tablename, $this->identifier . '=' . $params, null, $supports_revisions));
                $identifier = $this->identifier;
                $params     = array($identifier => $params); // Convert $params (given number value) into an key/value pair
            } else {
                // try to look up by sef_url
                $values = $db->selectArray($this->tablename, "sef_url='" . expString::sanitize($params) . "'", null, $supports_revisions, $needs_approval);
                // if we didn't find it via sef_url then we should check by title
                if (empty($values)) $values = $db->selectArray($this->tablename, "title='" . expString::sanitize($params) . "'", null, $supports_revisions, $needs_approval);
                $this->build($values);
                $params = array('title'=> $params);
            }
        } else {
            // Otherwise we assume that in inbound is an array or Object to be processed as is.        
            $this->build($params);
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,7 +104,7 @@
         $needs_approval = $this->needs_approval && ENABLE_WORKFLOW;
 
         // if the user passed in arguments to this constructor then we need to
-        // retrieve objects 
+        // retrieve objects
 
         // If a number was sent in, we assume this is a DB record ID, so pull it
         if (!is_object($params) && !is_array($params)) {
@@ -122,7 +122,7 @@
                 $params = array('title'=> $params);
             }
         } else {
-            // Otherwise we assume that in inbound is an array or Object to be processed as is.        
+            // Otherwise we assume that in inbound is an array or Object to be processed as is.
             $this->build($params);
         }
 
@@ -135,7 +135,7 @@
             $this->publish_date = $this->created_at;
         }
 
-        // setup the exception array if it's not there.  This array tells the getAssociatedObjectsForThisModel() function which 
+        // setup the exception array if it's not there.  This array tells the getAssociatedObjectsForThisModel() function which
         // modules NOT to setup.  This stops us from getting infinite loops with many to many relationships.
         if (is_array($params)){
             $params['except']         = isset($params['except']) ? $params['except'] : array();
@@ -180,6 +180,11 @@
         //eDebug("Supports Revisions:" . $this->supports_revisions);
 //        if ($this->supports_revisions && $range != 'revisions') $sql .= " AND revision_id=(SELECT MAX(revision_id) FROM `" . $db->prefix . $this->tablename . "` WHERE $where)";
 //        $sql .= empty($order) ? '' : ' ORDER BY ' . $order;
+        $order = expString::escape($order);
+        if ($limit !== null)
+            $limit = intval($limit);
+        if ($limitstart !== null)
+            $limitstart = intval($limitstart);
         $supports_revisions = $this->supports_revisions && ENABLE_WORKFLOW;
         if (ENABLE_WORKFLOW && $this->needs_approval) {
             $needs_approval = $user->id;
@@ -361,10 +366,10 @@
         foreach ($table as $col=> $colDef) {
             // check if the DB column has a corresponding value in the params array
             // if not, we check to see if the column is boolean...if so we set it to false
-            // if not, then we check to see if we had a previous value in this particular 
+            // if not, then we check to see if we had a previous value in this particular
             // record.  if so we reset it to itself so we don't lose the existing value.
-            // this is good for when the developer is trying to update just a field or two 
-            // in an existing record. 
+            // this is good for when the developer is trying to update just a field or two
+            // in an existing record.
             if (array_key_exists($col, $params)) {
                 $value = is_array($params) ? $params[$col] : $params->$col;
                 if ($colDef[0] == DB_DEF_INTEGER || $colDef[0] == DB_DEF_ID) {
@@ -464,7 +469,7 @@
 
         // Save this object's associated objects to the database.
         // FIXME: we're not going to do this automagically until we get the refreshing figured out.
-        //$this->saveAssociatedObjects(); 
+        //$this->saveAssociatedObjects();
 
         //Only grab fields that are valid and save this object
         $saveObj = new stdClass();
@@ -534,7 +539,7 @@
         }
 
         // safeguard again loc data not being pass via forms...sometimes this happens when you're in a router
-        // mapped view and src hasn't been passed in via link to the form 
+        // mapped view and src hasn't been passed in via link to the form
         if (isset($this->id) && empty($this->location_data)) {
             $loc = $db->selectValue($this->tablename, 'location_data', 'id=' . $this->id);
             if (!empty($loc)) $this->location_data = $loc;
```
