# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1478_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1478_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 152-192 of the vulnerable file.

													'" . $this->cache_id . "',
													'" . addslashes( $this->cache_name ) . "',
													'" . addslashes( serialize( $this->cache ) ) . "',
													'" . $now . "',
													'" . $this->cache_time . "',
													'" . addslashes( $this->cache_group ) . "',
													'" . addslashes( $this->cache_item ) . "')";
                    $this->cache_db->query( $sql );
                    break;
                case 'update':
                    $sql = "UPDATE
												 " . $cms_db['db_cache'] . " SET 
													val = '" . addslashes( serialize( $this->cache ) ) . "', 
													groups = '" . addslashes( $this->cache_group ) . "',
													item = '" . addslashes( $this->cache_item ) . "',
													changed = '" . $now . "',
													releasetime = '" . $this->cache_time . "'
													WHERE
													name = '" . addslashes( $this->cache_name ) . "'
													AND
													sid = '" . $this->cache_id . "'";
                    $this->cache_db->query( $sql );
                    break;
            } 
            $this->cache = array();
            $this->cache_id = 0;
            $this->cache_group = '';
            $this->cache_item = '';
            $this->cache_mode = '';
        } else $this->cache_mode = '';
    } 
    // delete old cache
    function delete_cache( $Cache_var = false ) {
        global $cms_db, $cache_gc, $cfg_cms;
        static $cache_gc;

        $this->init_cache();
        if ( ( !$cache_gc || $Cache_var ) && $this->use_cache ) {
            if ( $Cache_var !== true && $Cache_var != '' ) {
                list( $Cache_group, $Cache_item ) = explode( '_', $Cache_var );
            } 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -169,7 +169,7 @@
 													WHERE
 													name = '" . addslashes( $this->cache_name ) . "'
 													AND
-													sid = '" . $this->cache_id . "'";
+													sid = '" . addslashes( $this->cache_id ) . "'";
                     $this->cache_db->query( $sql );
                     break;
             } 
@@ -259,9 +259,9 @@
             $return = false;
             $sql = "SELECT val FROM
 								 " . $cms_db['db_cache'] . " WHERE
-									 name = '" . $this->cache_name . "'
+									 name = '" . addslashes( $this->cache_name ) . "'
 									 AND
-									 sid =  '" . $cache_id . "'";
+									 sid =  '" . addslashes( $cache_id ) . "'";
             if ( !$this->cache_db->query( $sql ) ) return;
             $oldmode = $this->cache_db->get_fetch_mode();
             $this->cache_db->set_fetch_mode( 'DB_FETCH_ASSOC' );
@@ -428,11 +428,11 @@
         $ret = true;
         $cquery = sprintf("select count(*) from %s where sid='%s' and name='%s'",
             $cms_db['sessions'],
-            $id,
-            $name);
+            addslashes($id),
+            addslashes($name));
         $squery = sprintf("select sid from %s where sid  = '%s' and name = '%s'",
             $cms_db['sessions'],
-            $id,
+            addslashes($id),
             addslashes($name));
         $this->db->query($squery);
         if ( $this->db->affected_rows() == 0
@@ -454,8 +454,8 @@
             $this->db->query(sprintf("delete from %s where name = '%s' and sid != '%s' and user_id = '%s'",
                 $cms_db[sessions],
                 addslashes($name),
-                $str,
-                $id));
+                addslashes($str),
+                addslashes($id)));
         }
     }
     function ac_sigleid($name, $id) {
@@ -467,11 +467,11 @@
             $ret = false;
             $cquery = sprintf("select count(*) from %s where user_id='%s' and name='%s'",
                 $cms_db['sessions'],
-                $id,
-                $name);
+                addslashes($id),
+                addslashes($name));
             $squery = sprintf("select sid from %s where user_id='%s' and name='%s'",
                 $cms_db['sessions'],
-                $id,
+                addslashes($id),
                 addslashes($name));
             $this->db->query($squery);
             if ( $this->db->affected_rows() == 0
```
