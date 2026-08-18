# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 398_10
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `398_10`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 257-297 of the vulnerable file.


                if($ok)
                {
                    $layout->navigate_notification(t(478, 'Item duplicated successfully.'), false, false, 'fa fa-check');
                    $out = blocks_form($item);
                }
                else
                {
                    $layout->navigate_notification(t(56, 'Unexpected error.'), false);
                    $item = new block();
                    $item->load(intval($_REQUEST['id']));
                    $out = blocks_form($item);
                }

                users_log::action($_REQUEST['fid'], $item->id, 'duplicate', $item->dictionary[$website->languages_list[0]]['title'], json_encode($_REQUEST));
            }
            break;

        case 'path':
		case 5:	// search an existing path
			$DB->query('SELECT path as id, path as label, path as value
						  FROM nv_paths
						 WHERE path LIKE '.protect('%'.$_REQUEST['term'].'%').' 
						   AND website = '.$website->id.'
				      ORDER BY path ASC
					     LIMIT 10',
						'array');
						
			echo json_encode($DB->result());
							  
			core_terminate();		
			break;

        case 'block_groups_list':
            $out = block_groups_list();
            break;

        case 'block_groups_json':	// block groups: json data retrieval
			$page = intval($_REQUEST['page']);
			$max	= intval($_REQUEST['rows']);
			$offset = ($page - 1) * $max;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -274,13 +274,17 @@
 
         case 'path':
 		case 5:	// search an existing path
-			$DB->query('SELECT path as id, path as label, path as value
+			$DB->query(
+			    'SELECT path as id, path as label, path as value
 						  FROM nv_paths
-						 WHERE path LIKE '.protect('%'.$_REQUEST['term'].'%').' 
+						 WHERE path LIKE :path 
 						   AND website = '.$website->id.'
 				      ORDER BY path ASC
 					     LIMIT 10',
-						'array');
+                'array',
+                array(
+                    ':path' => '%' . $_REQUEST['term'] . '%'
+                ));
 						
 			echo json_encode($DB->result());
 							  
```
