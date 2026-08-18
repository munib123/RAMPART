# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3583_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3583_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 83-123 of the vulnerable file.

                    }
                    break;
                case 'items': // Return items (use external file oc-admin/ajax/item_processing.php)
                    require_once osc_admin_base_path() . 'ajax/items_processing.php';
                    $items_processing = new ItemsProcessingAjax(Params::getParamsAsArray("get"));
                    break;
                case 'media': // Return items (use external file oc-admin/ajax/media_processing.php)
                    require_once osc_admin_base_path() . 'ajax/media_processing.php';
                    $media_processing = new MediaProcessingAjax(Params::getParamsAsArray("get"));
                    break;
                case 'categories_order': // Save the order of the categories
                    $aIds = Params::getParam('list');
                    $orderParent = 0;
                    $orderSub = 0;
                    $catParent = 0;

                    $catManager = Category::newInstance();

                    foreach ($aIds as $id => $parent) {
                        if ($parent == 'root') {
                            if (!$catManager->updateOrder($id, $orderParent)) {
                                $error = 1;
                            }
                            // set parent category 
                            $conditions = array('pk_i_id' => $id);
                            $array['fk_i_parent_id'] = NULL;
                            if (!$catManager->update($array, $conditions) > 0) {
                                $error = 1;
                            }
                            $orderParent++;
                        } else {
                            if ($parent != $catParent) {
                                $catParent = $parent;
                                $orderSub = 0;
                            }
                            if (!$catManager->updateOrder($id, $orderSub)) {
                                $error = 1;
                            }

                            // set parent category 
                            $conditions = array('pk_i_id' => $id);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,13 +100,15 @@
 
                     foreach ($aIds as $id => $parent) {
                         if ($parent == 'root') {
-                            if (!$catManager->updateOrder($id, $orderParent)) {
+                            $res = $catManager->updateOrder($id, $orderParent);
+                            if (is_bool($res) && !$res) {
                                 $error = 1;
                             }
                             // set parent category 
                             $conditions = array('pk_i_id' => $id);
                             $array['fk_i_parent_id'] = NULL;
-                            if (!$catManager->update($array, $conditions) > 0) {
+                            $res = $catManager->update($array, $conditions);
+                            if (is_bool($res) && !$res) {
                                 $error = 1;
                             }
                             $orderParent++;
@@ -115,31 +117,31 @@
                                 $catParent = $parent;
                                 $orderSub = 0;
                             }
-                            if (!$catManager->updateOrder($id, $orderSub)) {
+                            
+                            $res = $catManager->updateOrder($id, $orderSub);
+                            if (is_bool($res) && !$res ) {
                                 $error = 1;
                             }
 
                             // set parent category 
                             $conditions = array('pk_i_id' => $id);
                             $array['fk_i_parent_id'] = $catParent;
-                            if (!$catManager->update($array, $conditions) > 0) {
+                            
+                            $res = $catManager->update($array, $conditions);
+                            if (is_bool($res) && !$res) {
                                 $error = 1;
                             }
                             $orderSub++;
                         }
                     }
 
-                    $result = "{";
-                    $error = 0;
-
-                    if ($error) {
-                        $result .= '"error" : "' . __("Some error ocurred") . '"';
-                    } else {
-                        $result .= '"ok" : "' . __("Order saved") . '"';
-                    }
-                    $result .= "}";
-
-                    echo $result;
+                    if($error) {
+                        $result = array( 'error' => __("Some error ocurred") ) ;
+                    } else {
+                        $result = array( 'ok' => __("Order saved") ) ;
+                    }
+                    echo json_encode($result) ;
+                    
                     break;
                 case 'category_edit_iframe':
                     $this->_exportVariableToView( 'category', Category::newInstance()->findByPrimaryKey( Params::getParam("id") ) ) ;
@@ -158,66 +160,73 @@
                     break;
                 case 'field_categories_post':
                     $error = 0;
-                    if (!$error) {
-                        try {
-                            $field = Field::newInstance()->findByName(Params::getParam("s_name"));
-                            if (!isset($field['pk_i_id']) || (isset($field['pk_i_id']) && $field['pk_i_id'] == Params::getParam("id"))) {
-                                Field::newInstance()->cleanCategoriesFromField(Params::getParam("id"));
-                                $slug = Params::getParam("field_slug") != '' ? Params::getParam("field_slug") : Params::getParam("id");
-                                $slug = preg_replace('|([-]+)|', '-', preg_replace('|[^a-z0-9_-]|', '-', strtolower($slug)));
-                                Field::newInstance()->update(array('s_name' => Params::getParam("s_name"), 'e_type' => Params::getParam("field_type"), 's_slug' => $slug, 'b_required' => Params::getParam("field_required") == "1" ? 1 : 0, 's_options' => Params::getParam('s_options')), array('pk_i_id' => Params::getParam("id")));
-                                Field::newInstance()->insertCategories(Params::getParam("id"), Params::getParam("categories"));
-                            } else {
+                    $field = Field::newInstance()->findByName(Params::getParam("s_name"));
+                    
+                    if (!isset($field['pk_i_id']) || (isset($field['pk_i_id']) && $field['pk_i_id'] == Params::getParam("id"))) {
+                        // remove categories from a field
+                        Field::newInstance()->cleanCategoriesFromField(Params::getParam("id"));
+                        // no error... continue updating fields
+                        if($error == 0) {
+                            $slug = Params::getParam("field_slug") != '' ? Params::getParam("field_slug") : Params::getParam("id");
+                            $slug = preg_replace('|([-]+)|', '-', preg_replace('|[^a-z0-9_-]|', '-', strtolower($slug)));
+                            $res = Field::newInstance()->update(array('s_name' => Params::getParam("s_name"), 'e_type' => Params::getParam("field_type"), 's_slug' => $slug, 'b_required' => Params::getParam("field_required") == "1" ? 1 : 0, 's_options' => Params::getParam('s_options')), array('pk_i_id' => Params::getParam("id")));
+                            if(is_bool($res) && !$res) {
                                 $error = 1;
-                                $message = __("Sorry, you already have one field with that name");
-                            }
-                        } catch (Exception $e) {
-                            $error = 1;
+                            }
+                        }
+                        // no error... continue inserting categories-field
+                        if($error == 0) {
+                            $aCategories = Params::getParam("categories");
+                            if( is_array($aCategories) && count($aCategories) > 0) {
+                                $res = Field::newInstance()->insertCategories(Params::getParam("id"), $aCategories);
+                                if(!$res) {
+                                    $error = 1;
+                                }
+                            }
+                        }
+                        // error while updating?
+                        if($error == 1) {
                             $message = __("Error while updating.");
                         }
-                    }
-
-                    $result = "{";
-                    if ($error) {
-                        $result .= '"error" : "';
-                        $result .= $message;
-                        $result .= '"';
-                    } else {
-                        $result .= '"ok" : "' . __("Saved") . '", "text" : "' . Params::getParam("s_name") . '"';
-                    }
-                    $result .= "}";
-
-                    echo $result;
+                    } else {
+                        $error = 1;
+                        $message = __("Sorry, you already have one field with that name");
+                    }
+
+                    if($error) {
+                        $result = array( 'error' => $message) ;
+                    } else {
+                        $result = array( 'ok' => __("Saved") , 'text' => Params::getParam("s_name")) ;
+                    }
+                    
+                    echo json_encode($result) ;
+                    
                     break;
                 case 'delete_field':
                     $id = Params::getParam("id");
                     $error = 0;
 
-                    try {
-                        $fieldManager = Field::newInstance();
-                        $fieldManager->deleteByPrimaryKey($id);
-
+                    $fieldManager = Field::newInstance();
+                    $res = $fieldManager->deleteByPrimaryKey($id);
... (diff truncated)
```
