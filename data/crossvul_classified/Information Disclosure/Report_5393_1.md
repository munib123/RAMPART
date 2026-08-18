# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5393_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5393_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 2116-2156 of the vulnerable file.


        $sessAr = expSession::get('verify_shopper');
        if (isset($sessAr)) {
            order::setCartCookie($order);
            $orig_path = $sessAr['orig_path'];
            expSession::un_set('verify_shopper');
            redirect_to($orig_path);
        } else {
            expHistory::back();
        }
    }

    /**
     * AJAX search for internal (addressController) addresses
     *
     */
    public function search() {
//        global $db, $user;
        global $db;

        $sql = "select DISTINCT(a.id) as id, a.firstname as firstname, a.middlename as middlename, a.lastname as lastname, a.organization as organization, a.email as email ";
        $sql .= "from " . $db->prefix . "addresses as a "; //R JOIN " .
        //$db->prefix . "billingmethods as bm ON bm.addresses_id=a.id ";
        $sql .= " WHERE match (a.firstname,a.lastname,a.email,a.organization) against ('" . $this->params['query'] .
            "*' IN BOOLEAN MODE) ";
        $sql .= "order by match (a.firstname,a.lastname,a.email,a.organization)  against ('" . $this->params['query'] . "*' IN BOOLEAN MODE) ASC LIMIT 12";
        $res = $db->selectObjectsBySql($sql);
        foreach ($res as $key=>$record) {
            $res[$key]->title = $record->firstname . ' ' . $record->lastname;
        }
        //eDebug($sql);
        $ar = new expAjaxReply(200, gt('Here\'s the items you wanted'), $res);
        $ar->send();
    }

    /**
     * Ajax search for external addresses
     *
     */
    public function search_external() {
//        global $db, $user;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2133,6 +2133,7 @@
 //        global $db, $user;
         global $db;
 
+        $this->params['query'] = expString::escape($this->params['query']);
         $sql = "select DISTINCT(a.id) as id, a.firstname as firstname, a.middlename as middlename, a.lastname as lastname, a.organization as organization, a.email as email ";
         $sql .= "from " . $db->prefix . "addresses as a "; //R JOIN " .
         //$db->prefix . "billingmethods as bm ON bm.addresses_id=a.id ";
@@ -2156,6 +2157,7 @@
 //        global $db, $user;
         global $db;
 
+        $this->params['query'] = expString::escape($this->params['query']);
         $sql = "select DISTINCT(a.id) as id, a.source as source, a.firstname as firstname, a.middlename as middlename, a.lastname as lastname, a.organization as organization, a.email as email ";
         $sql .= "from " . $db->prefix . "external_addresses as a "; //R JOIN " .
         //$db->prefix . "billingmethods as bm ON bm.addresses_id=a.id ";
```
