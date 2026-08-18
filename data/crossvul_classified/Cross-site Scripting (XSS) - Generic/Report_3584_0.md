# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3584_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3584_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 50-90 of the vulnerable file.

 * 
 * @package cms
 * @subpackage content
 */
class SilverStripeNavigatorItem extends Object {
	function getHTML($page) {}
	function getMessage($page) {}
}

/**
 * @package cms
 * @subpackage content
 */
class SilverStripeNavigatorItem_CMSLink extends SilverStripeNavigatorItem {
	static $priority = 10;	
	
	function getHTML($page) {
		if(is_a(Controller::curr(), 'CMSMain')) {
			return '<a class="current">CMS</a>';
		} else {
			$cmsLink = 'admin/show/' . $page->ID;
			$cmsLink = "<a href=\"$cmsLink\" class=\"newWindow\" target=\"cms\">". _t('ContentController.CMS', 'CMS') ."</a>";
	
			return $cmsLink;
		}
	}
	
	function getLink($page) {
		if(is_a(Controller::curr(), 'CMSMain')) {
			return Controller::curr()->AbsoluteLink('show') . $page->ID;
		}
	}

}

/**
 * @package cms
 * @subpackage content
 */
class SilverStripeNavigatorItem_StageLink extends SilverStripeNavigatorItem {
	static $priority = 20;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,7 +67,7 @@
 		if(is_a(Controller::curr(), 'CMSMain')) {
 			return '<a class="current">CMS</a>';
 		} else {
-			$cmsLink = 'admin/show/' . $page->ID;
+			$cmsLink = Convert::raw2att('admin/show/' . $page->ID);
 			$cmsLink = "<a href=\"$cmsLink\" class=\"newWindow\" target=\"cms\">". _t('ContentController.CMS', 'CMS') ."</a>";
 	
 			return $cmsLink;
@@ -96,7 +96,7 @@
 		} else {
 			$draftPage = Versioned::get_one_by_stage('SiteTree', 'Stage', '"SiteTree"."ID" = ' . $page->ID);
 			if($draftPage) {
-				$pageLink = Controller::join_links($draftPage->AbsoluteLink(), "?stage=Stage");
+				$pageLink = Convert::raw2att(Controller::join_links($draftPage->AbsoluteLink(), "?stage=Stage"));
 				return "<a href=\"$pageLink\" class=\"newWindow\" target=\"site\" style=\"left : -1px;\">". _t('ContentController.DRAFTSITE', 'Draft Site') ."</a>";
 			}
 		}
@@ -128,7 +128,7 @@
 		} else {
 			$livePage = Versioned::get_one_by_stage('SiteTree', 'Live', '"SiteTree"."ID" = ' . $page->ID);
 			if($livePage) {
-				$pageLink = Controller::join_links($livePage->AbsoluteLink(), "?stage=Live");
+				$pageLink = Convert::raw2att(Controller::join_links($livePage->AbsoluteLink(), "?stage=Live"));
 				return "<a href=\"$pageLink\" class=\"newWindow\" target=\"site\" style=\"left : -3px;\">". _t('ContentController.PUBLISHEDSITE', 'Published Site') ."</a>";
 			}
 		}
@@ -165,7 +165,7 @@
 				(!$currentDraft || ($currentDraft && $page->Version != $currentDraft->Version)) 
 				&& (!$currentLive || ($currentLive && $page->Version != $currentLive->Version))
 			) {
-				$pageLink = $page->AbsoluteLink();
+				$pageLink = Convert::raw2att($page->AbsoluteLink());
 				return "<a href=\"$pageLink?archiveDate={$page->LastEdited}\" class=\"newWindow\" target=\"site\" style=\"left : -3px;\">". _t('ContentController.ARCHIVEDSITE', 'Archived Site') ."</a>";
 			}
 		}
```
