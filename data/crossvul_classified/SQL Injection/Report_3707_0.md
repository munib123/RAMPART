# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3707_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3707_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 73-115 of the vulnerable file.

                    $this->set_error_message(array(
                        "error" => $this->api_service->get_error_msg(001, 'iso')
                    ));
                                        
                    return;
                }
                else
                {
                    $this->response_data = $this->_get_country_by_iso($this->request['iso']);
                }
            break;
            
            default:
                $this->response_data = $this->_get_countries_by_all();
        }
    }

    /**
     * Fetch all countries
     *
     * @param string where - the where clause for sql
     * @param string limit - the limit number
     * @param string response_type - XML or JSON
     *
     * @return string 
     */
    private function _get_countries($where = '', $limit = '')
    {

        // Fetch countries
        $this->query = "SELECT id, iso, country as `name`, capital
            FROM `".$this->table_prefix."country` $where $limit";

        $items = $this->db->query($this->query);
        
        // Set the record count
        $this->record_count = $items->count();
        
        $i = 0;

        $json_countries = array();
        $ret_json_or_xml = '';
        
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,31 +90,35 @@
     /**
      * Fetch all countries
      *
-     * @param string where - the where clause for sql
-     * @param string limit - the limit number
-     * @param string response_type - XML or JSON
+     * @param array where - array to pass to query builder
+     * @param integer limit - number of results to return
      *
      * @return string 
      */
-    private function _get_countries($where = '', $limit = '')
+    private function _get_countries($where = array(), $limit = FALSE)
     {
 
         // Fetch countries
-        $this->query = "SELECT id, iso, country as `name`, capital
-            FROM `".$this->table_prefix."country` $where $limit";
-
-        $items = $this->db->query($this->query);
-        
+				$items = ORM::factory('Country')
+						->select('country as name', 'country.*')
+						->where($where)
+						->orderby('id','DESC');
+				
+				if ($limit)
+					$items->limit($limit);
+				
+				$items = $items->find_all();
+				
         // Set the record count
-        $this->record_count = $items->count();
+        $this->record_count = count($items);
         
         $i = 0;
 
         $json_countries = array();
         $ret_json_or_xml = '';
         
-        //No record found.
-        if ($items->count() == 0)
+				//No record found.
+        if ($this->record_count == 0)
         {
             return $this->response(4);
         }
@@ -125,12 +129,12 @@
             // Needs different treatment depending on the output
             if ($this->response_type == 'json')
             {
-                $json_countries[] = array("country" => $item);
+                $json_countries[] = array("country" => $item->as_array());
             } 
             else 
             {
                 $json_countries['country'.$i] = array(
-                        "country" => $item);
+                        "country" => $item->as_array());
 
                 $this->replar[] = 'country'.$i;
             }
@@ -168,8 +172,7 @@
      */
     private function _get_countries_by_all()
     {
-        $where = "ORDER by id DESC "; 
-        return $this->_get_countries($where);
+        return $this->_get_countries();
     }
 
     /**
@@ -180,11 +183,9 @@
      */
     private function _get_country_by_name($name)
     {
-        $where = "\n WHERE country = '$name' ";
-        $where .= "ORDER by id DESC";
-        $limit = "\nLIMIT 0, $this->list_limit";
-        
-        return $this->_get_countries($where, $limit);
+				$where = array('country' => $name);
+        
+        return $this->_get_countries($where, $this->list_limit);
     }
 
     /**
@@ -195,11 +196,9 @@
      */
     private function _get_country_by_id($id)
     {
-        $where = "\n WHERE id=$id ";
-        $where .= "ORDER by id DESC";
-        $limit = "\nLIMIT 0, $this->list_limit";
-        
-        return $this->_get_countries($where, $limit);
+        $where = array('id' => $id);
+        
+        return $this->_get_countries($where, $this->list_limit);
     }
 
     /**
@@ -209,11 +208,8 @@
      */
     private function _get_country_by_iso($iso)
     {
-        $where = "\n WHERE iso='$iso' ";
-        $where .= "ORDER by id DESC";
-        $limit = "\nLIMIT 0, $this->list_limit";
-        return $this->_get_countries($where, $limit);
+        $where = array('iso' => $iso);
+        return $this->_get_countries($where, $this->list_limit);
     }
 }
 
-?>
```
