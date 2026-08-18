# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 398_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `398_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 167-207 of the vulnerable file.

            $func = new stdClass();
            $func->id = 'grid_notes';
            $func->codename = 'grid_notes';
            $func->category = 'content';
            $func->icon = '';
            $func->lid = '';
            $func->enabled = 1;
            break;

        case 'permissions':
            $func = new stdClass();
            $func->id = 'permissions';
            $func->codename = 'permissions';
            $func->category = 'config';
            $func->icon = '';
            $func->lid = '';
            $func->enabled = 1;
            break;

        default:
            if(is_numeric($fid))
                $where = 'id = '.intval($fid);
            else
                $where = 'codename = '.protect($fid);

            $DB->query('SELECT *
                          FROM nv_functions
                         WHERE '.$where.'
                           AND enabled = 1');

            $func = $DB->first();

            if(!$menu_layout->function_is_displayed($func->id))
                $func = false;
    }

    return $func;
}


/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -184,15 +184,22 @@
             break;
 
         default:
+            $query_params = NULL;
             if(is_numeric($fid))
+            {
                 $where = 'id = '.intval($fid);
+            }
             else
-                $where = 'codename = '.protect($fid);
-
-            $DB->query('SELECT *
-                          FROM nv_functions
-                         WHERE '.$where.'
-                           AND enabled = 1');
+            {
+                $where = 'codename = :codename';
+                $query_params = array(':codename' => $fid);
+            }
+
+            $DB->query(
+                'SELECT * FROM nv_functions WHERE '.$where.' AND enabled = 1',
+                'object',
+                $query_params
+            );
 
             $func = $DB->first();
 
@@ -1179,9 +1186,9 @@
         $title_color = '#595959';
         $text_color = '#595959';
 
-        $background_color_db = $DB->query_single('value', 'nv_permissions', 'name = ' . protect("nvweb.comments.background_color") . ' AND website = ' . protect($website->id), 'id DESC');
-        $text_color_db = $DB->query_single('value', 'nv_permissions', 'name = ' . protect("nvweb.comments.text_color") . ' AND website = ' . protect($website->id), 'id DESC');
-        $title_color_db = $DB->query_single('value', 'nv_permissions', 'name = ' . protect("nvweb.comments.titles_color") . ' AND website = ' . protect($website->id), 'id DESC');
+        $background_color_db = $DB->query_single('value', 'nv_permissions', 'name = "nvweb.comments.background_color" AND website = ' . intval($website->id), 'id DESC');
+        $text_color_db = $DB->query_single('value', 'nv_permissions', 'name = "nvweb.comments.text_color" AND website = ' . intval($website->id), 'id DESC');
+        $title_color_db = $DB->query_single('value', 'nv_permissions', 'name = "nvweb.comments.titles_color" AND website = ' . intval($website->id), 'id DESC');
 
         if (!empty($background_color_db))
             $background_color = str_replace('"', '', $background_color_db);
```
