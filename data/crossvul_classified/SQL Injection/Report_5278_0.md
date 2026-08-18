# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5278_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5278_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 362-402 of the vulnerable file.

    }

    /**
     * Select a series of objects
     *
     * Selects a set of objects from the database.  Because of the way
     * Exponent handles objects and database tables, this is akin to
     * SELECTing a set of records from a database table.  Returns an
     * array of objects, in any random order.
     *
     * @param string $table The name of the table/object to look at
     * @param string $where Criteria used to narrow the result set.  If this
     *   is specified as null, then no criteria is applied, and all objects are
     *   returned
     * @param null $orderby
     * @return array
     */
    function selectObjects($table, $where = null, $orderby = null) {
        if ($where == null)
            $where = "1";
        if ($orderby == null)
            $orderby = '';
        else
            $orderby = "ORDER BY " . $orderby;

        $res = @mysqli_query($this->connection, "SELECT * FROM `" . $this->prefix . "$table` WHERE $where $orderby");
        if ($res == null)
            return array();
        $objects = array();
        for ($i = 0, $iMax = mysqli_num_rows($res); $i < $iMax; $i++)
            $objects[] = mysqli_fetch_object($res);
        return $objects;
    }

	/**
	 * @param  $terms
	 * @param null $where
	 * @return array
	 */
    function selectSearch($terms, $where = null) {
        if ($where == null)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -379,6 +379,8 @@
     function selectObjects($table, $where = null, $orderby = null) {
         if ($where == null)
             $where = "1";
+        else
+            $where = $this->injectProof($where);
         if ($orderby == null)
             $orderby = '';
         else
@@ -484,7 +486,7 @@
         //$lfh = fopen($logFile, 'a');
         //fwrite($lfh, $sql . "\n");    
         //fclose($lfh);                 
-        $res = @mysqli_query($this->connection, $sql);
+        $res = @mysqli_query($this->connection, $this->injectProof($sql));
         if ($res == null)
             return null;
         return mysqli_fetch_object($res);
@@ -497,7 +499,7 @@
 	 * @return array
 	 */
     function selectObjectsBySql($sql) {
-        $res = @mysqli_query($this->connection, $sql);
+        $res = @mysqli_query($this->connection, $this->injectProof($sql));
         if ($res == null)
             return array();
         $objects = array();
@@ -638,6 +640,8 @@
     function selectObjectsIndexedArray($table, $where = null, $orderby = null) {
         if ($where == null)
             $where = "1";
+        else
+            $where = $this->injectProof($where);
         if ($orderby == null)
             $orderby = '';
         else
@@ -722,6 +726,7 @@
      * @return object/null|void
      */
     function selectObject($table, $where) {
+        $where = $this->injectProof($where);
         $res = mysqli_query($this->connection, "SELECT * FROM `" . $this->prefix . "$table` WHERE $where LIMIT 0,1");
         if ($res == null)
             return null;
@@ -773,7 +778,7 @@
                 if ($values != ") VALUES (") {
                     $values .= ",";
                 }
-                $values .= "'" . mysqli_real_escape_string($this->connection, $val) . "'";
+                $values .= "'" . $this->escapeString($val) . "'";
             }
         }
         $sql = substr($sql, 0, -1) . substr($values, 0) . ")";
@@ -836,13 +841,13 @@
                     $val = serialize($val);   
                     $sql .= "`$var`='".$val."',";
                 } else {
-                    $sql .= "`$var`='".mysqli_real_escape_string($this->connection,$val)."',";
+                    $sql .= "`$var`='" . $this->escapeString($val) . "',";
                 }
             }
         }
         $sql = substr($sql, 0, -1) . " WHERE ";
         if ($where != null)
-            $sql .= $where;
+            $sql .= $this->injectProof($where);
         else
             $sql .= "`" . $identifier . "`=" . $object->$identifier;
         //if ($table == 'text') eDebug($sql,true);        
@@ -1130,6 +1135,8 @@
     function selectArrays($table, $where = null, $orderby = null) {
         if ($where == null)
             $where = "1";
+        else
+            $where = $this->injectProof($where);
         if ($orderby == null)
             $orderby = '';
         else
@@ -1156,7 +1163,7 @@
      * @return array
      */
     function selectArraysBySql($sql) {        
-        $res = @mysqli_query($this->connection, $sql);
+        $res = @mysqli_query($this->connection, $this->injectProof($sql));
         if ($res == null)
             return array();
         $arrays = array();
@@ -1185,6 +1192,8 @@
     function selectArray($table, $where = null, $orderby = null, $is_revisioned=false, $needs_approval=false) {
         if ($where == null)
             $where = "1";
+        else
+            $where = $this->injectProof($where);
         $as = '';
         if ($is_revisioned) {
    //            $where.= " AND revision_id=(SELECT MAX(revision_id) FROM `" . $this->prefix . "$table` WHERE $where)";
@@ -1223,6 +1232,8 @@
     function selectExpObjects($table, $where=null, $classname, $get_assoc=true, $get_attached=true, $except=array(), $cascade_except=false, $order=null, $limitsql=null, $is_revisioned=false, $needs_approval=false) {
         if ($where == null)
             $where = "1";
+        else
+            $where = $this->injectProof($where);
         $as = '';
         if ($is_revisioned) {
    //            $where.= " AND revision_id=(SELECT MAX(revision_id) FROM `" . $this->prefix . "$table` WHERE $where)";
@@ -1259,7 +1270,7 @@
      * @return array
      */
     function selectExpObjectsBySql($sql, $classname, $get_assoc=true, $get_attached=true) {
-        $res = @mysqli_query($this->connection, $sql);
+        $res = @mysqli_query($this->connection, $this->injectProof($sql));
         if ($res == null)
             return array();
         $arrays = array();
```
