# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2379_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2379_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1006-1046 of the vulnerable file.

                        }
                    }
                }
            }
        }

        if (!empty($ids)) {

            $ids = array_unique($ids);

            return $ids;
        } else {

            return false;
        }
    }

    public function get_children($parent_id = 0, $type = false, $visible_on_frontend = false)
    {

        $categories_id = intval($parent_id);
        $cache_group = 'categories/' . $categories_id;

        $table = $this->tables['categories'];

        $db_t_content = $this->tables['content'];

        if (isset($orderby) == false) {
            $orderby = array();
            //$orderby[0] = 'updated_on';

            //$orderby[1] = 'DESC';

            $orderby[0] = 'position';

            $orderby[1] = 'asc';
        }

        if (intval($parent_id) == 0) {

            return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1023,7 +1023,7 @@
     public function get_children($parent_id = 0, $type = false, $visible_on_frontend = false)
     {
 
-        $categories_id = intval($parent_id);
+        $categories_id = $parent_id =intval($parent_id);
         $cache_group = 'categories/' . $categories_id;
 
         $table = $this->tables['categories'];
```
