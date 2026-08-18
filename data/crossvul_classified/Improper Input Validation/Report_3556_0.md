# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3556_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3556_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 205-245 of the vulnerable file.

			self::set_use_ajax_commenting(false);
		}
		
		// Shall We use AJAX?
		if(self::$use_ajax_commenting) {
			Requirements::javascript(SAPPHIRE_DIR . '/thirdparty/behaviour/behaviour.js');
			Requirements::javascript(SAPPHIRE_DIR . '/thirdparty/prototype/prototype.js');
			Requirements::javascript(THIRDPARTY_DIR . '/scriptaculous/effects.js');
			Requirements::javascript(CMS_DIR . '/javascript/PageCommentInterface.js');
		}
		
		$this->extend('updatePageCommentForm', $form);
		
		// Load the users data from a cookie
		$cookie = Cookie::get('PageCommentInterface_Data');
		if($cookie) {
			$visibleFields = array();
			foreach($fields as $field) {
				if(!$field instanceof HiddenField) $visibleFields[] = $field->Name();
			}
			$form->loadDataFrom(unserialize($cookie), false, $visibleFields);
		}

		return $form;
	}
	
	function Comments() {
		// Comment limits
		$limit = array();
		$limit['start'] = isset($_GET['commentStart']) ? (int)$_GET['commentStart'] : 0;
		$limit['limit'] = PageComment::$comments_per_page;
		
		$spamfilter = isset($_GET['showspam']) ? '' : "AND \"IsSpam\" = 0";
		$unmoderatedfilter = Permission::check('CMS_ACCESS_CommentAdmin') ? '' : "AND \"NeedsModeration\" = 0";
		$order = self::$order_comments_by;
		$comments =  DataObject::get("PageComment", "\"ParentID\" = '" . Convert::raw2sql($this->page->ID) . "' $spamfilter $unmoderatedfilter", $order, "", $limit);
		
		if(is_null($comments)) {
			return;
		}
		
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -222,7 +222,7 @@
 			foreach($fields as $field) {
 				if(!$field instanceof HiddenField) $visibleFields[] = $field->Name();
 			}
-			$form->loadDataFrom(unserialize($cookie), false, $visibleFields);
+			$form->loadDataFrom(Convert::json2array($cookie), false, $visibleFields);
 		}
 
 		return $form;
@@ -272,7 +272,7 @@
  */
 class PageCommentInterface_Form extends Form {
 	function postcomment($data) {
-		Cookie::set("PageCommentInterface_Data", serialize($data));
+		Cookie::set("PageCommentInterface_Data", Convert::raw2json($data));
 
 		// Spam filtering
 		if(SSAkismet::isEnabled()) {
@@ -333,7 +333,7 @@
 		$comment->write();
 		
 		unset($data['Comment']);
-		Cookie::set("PageCommentInterface_Data", serialize($data));
+		Cookie::set("PageCommentInterface_Data", Convert::raw2json($data));
 		
 		$moderationMsg = _t('PageCommentInterface_Form.AWAITINGMODERATION', "Your comment has been submitted and is now awaiting moderation.");
 		
```
