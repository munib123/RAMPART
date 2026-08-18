# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3705_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3705_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 30-72 of the vulnerable file.

            $this->by = $this->request['by'];
        }
                
        switch ($this->by)
        {
            case "latlon":
            break;
            
            // Get location by id
            case "locid":
                if ( ! $this->api_service->verify_array_index($this->request, 'id'))
                {
                    $this->set_error_message(array(
                        "error" => $this->api_service->get_error_msg(001, 'id')
                    ));
                    
                    return;
                }
                else
                {
                    $this->response_data = $this->_get_locations(array(
                    	'id = '.$this->request['id']
                    ));
                }
            break;
            
            // Get locations by country id
            case "country":
                if ( ! $this->api_service->verify_array_index($this->request, 'id'))
                {
                    $this->set_error_message(array(
                        "error" => $this->api_service->get_error_msg(001, 'id')
                    ));
                    
                    return;
                }
                else
                {
                    $this->response_data = $this->_get_locations(array('country_id' => $this->request['id']));
                }
            break;
            
            default:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,9 +47,7 @@
                 }
                 else
                 {
-                    $this->response_data = $this->_get_locations(array(
-                    	'id = '.$this->request['id']
-                    ));
+                    $this->response_data = $this->_get_locations(array('id' => $this->request['id']));
                 }
             break;
             
@@ -83,7 +81,12 @@
 	private function _get_locations($where = array())
 	{
 		// Fetch the location items
-		$items = Location_Model::get_locations($where, $this->list_limit);
+		$items = ORM::factory('Location')
+				->select('location_name AS name', 'location.*') // Add extra name field for backwards compat
+				->where($where)
+				->where('location_visible', 1)
+				->limit($this->list_limit)
+				->find_all();
         
 		//No record found.
 		if ($items->count() == 0)
@@ -99,6 +102,10 @@
 		
 		foreach ($items as $item)
 		{
+			$item = $item->as_array();
+			// Hide variables we don't want publicly exposed
+			unset($item['location_visible']);
+			
 			// Needs different treatment depending on the output
 			if ($this->response_type == 'json')
 			{
```
