# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5398_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5398_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 11-51 of the vulnerable file.

# Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# GPL: http://www.gnu.org/licenses/gpl.txt
#
##################################################

/**
 * This is the class expRatingController
 *
 * @package Core
 * @subpackage Controllers
 */

class expRatingController extends expController {
    public $base_class = 'expRating';

    static function displayname() { return gt("Ratings Manager"); }
    static function description() { return gt("This module is for managing ratings on records"); }
    static function hasSources() { return false; }
	
	function __construct($src=null, $params=array()) {
        global $user;
	    parent::__construct($src, $params);
        $this->remove_permissions = ($user->isLoggedIn())?array('update','create'):array();
    }

    /**
     * Update rating...handled via ajax
     */
    function update() {
        global $db, $user;
        	
        $this->params['id'] = $db->selectValue('content_expRatings','expratings_id',"content_id='".$this->params['content_id']."' AND content_type='".$this->params['content_type']."' AND subtype='".$this->params['subtype']."' AND poster='".$user->id."'");
        $msg = gt('Thank you for your rating');
        $rating = new expRating($this->params);
        if (!empty($rating->id)) $msg = gt('Your rating has been adjusted');
        // save the rating
        $rating->update($this->params);

        // attach the rating to the datatype it belongs to (blog, news, etc..);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,7 +28,7 @@
     static function displayname() { return gt("Ratings Manager"); }
     static function description() { return gt("This module is for managing ratings on records"); }
     static function hasSources() { return false; }
-	
+
 	function __construct($src=null, $params=array()) {
         global $user;
 	    parent::__construct($src, $params);
@@ -40,7 +40,9 @@
      */
     function update() {
         global $db, $user;
-        	
+
+        $this->params['content_type'] = preg_replace("/[^[:alnum:][:space:]]/u", '', $this->params['content_type']);
+        $this->params['subtype'] = preg_replace("/[^[:alnum:][:space:]]/u", '', $this->params['subtype']);
         $this->params['id'] = $db->selectValue('content_expRatings','expratings_id',"content_id='".$this->params['content_id']."' AND content_type='".$this->params['content_type']."' AND subtype='".$this->params['subtype']."' AND poster='".$user->id."'");
         $msg = gt('Thank you for your rating');
         $rating = new expRating($this->params);
@@ -59,11 +61,11 @@
 
         $ar = new expAjaxReply(200,$msg);
         $ar->send();
-		
+
         // flash('message', $msg);
         // expHistory::back();
 	}
-	
+
 }
 
 ?>
```
