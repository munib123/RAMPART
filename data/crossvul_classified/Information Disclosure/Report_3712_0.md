# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 3712_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3712_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 170-210 of the vulnerable file.

                    "error" => $this->api_service->get_error_msg(002)
                ));
        }
    }
        
    /**
     * Gets a list of comments by
     * 
     * @param string status - List comments by status.
     * @param string response_type - XML or JSON
     * 
     * @return array
     */
    private function _get_comment_list($where, $limit = '') 
    {
       
        $xml = new XMLWriter();
        $json = array();
        $json_item = array();

        $this->query = "SELECT * FROM comment $where $limit";
        
        $items = $this->db->query($this->query);

        // Set the no. of records returned
        $this->record_count = $items->count();
        
        if ($this->response_type == "xml") 
        {
            $xml->openMemory();
            $xml->startDocument('1.0', 'UTF-8');
            $xml->startElement('response');
            $xml->startElement('payload');
            $xml->writeElement('domain',$this->domain);
            $xml->startElement('comments');
        }
        
        //No record found.
        if ($items->count() == 0)
        {
            return $this->response(4);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -187,7 +187,7 @@
         $json = array();
         $json_item = array();
 
-        $this->query = "SELECT * FROM comment $where $limit";
+        $this->query = "SELECT id, incident_id, comment_author, comment_description, comment_date, user_id FROM comment $where $limit";
         
         $items = $this->db->query($this->query);
 
@@ -225,14 +225,9 @@
                 $xml->writeElement('user_id',$list_item->user_id);
                 $xml->writeElement('comment_author',
                         $list_item->comment_author);
-                $xml->writeElement('comment_email',
-                        $list_item->comment_email);
                 $xml->writeElement('comment_description',
                         $list_item->comment_description);
-                $xml->writeElement('comment_ip',$list_item->comment_ip);
-                $xml->writeElement('comment_active',
-                        $list_item->comment_active);
-                $xml->writeElement('comment_date',$list_item->comment_date);
+               $xml->writeElement('comment_date',$list_item->comment_date);
                     
                 $xml->endElement(); // comment
             }
@@ -802,8 +797,8 @@
 			$incident_comments = array();
 			if ($id)
 			{
-				$this->query = "SELECT id, incident_id, comment_author, comment_email, ";
-				$this->query .= "comment_description,comment_date ";
+				$this->query = "SELECT id, incident_id, comment_author, ";
+				$this->query .= "comment_description, comment_date ";
 				$this->query .= "FROM ".$this->table_prefix."`comment`" ;
 				$this->query .= " WHERE `incident_id` = ".$this->db->escape_str($id)." AND `comment_active` = '1' ";
 				$this->query .= "AND `comment_spam` = '0' ORDER BY `comment_date` ASC";
@@ -877,8 +872,8 @@
 			$checkin_comments = array();
 			if ($id)
 			{
-				$this->query = "SELECT id, checkin_id, comment_author, comment_email, ";
-				$this->query .= "comment_description,comment_date ";
+				$this->query = "SELECT id, checkin_id, comment_author, ";
+				$this->query .= "comment_description, comment_date ";
 				$this->query .= "FROM ".$this->table_prefix."`comment`" ;
 				$this->query .= " WHERE `checkin_id` = ".$this->db->escape_str($id)." AND `comment_active` = '1' ";
 				$this->query .= "AND `comment_spam` = '0' ORDER BY `comment_date` ASC";
```
