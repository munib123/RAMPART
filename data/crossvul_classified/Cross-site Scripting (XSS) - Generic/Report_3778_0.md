# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3778_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3778_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 6-44 of the vulnerable file.

 * For the full copyright and license information, please view the license
 * file that was distributed with this source code.
 */

/**
 * This is the autocomplete-action, it will output a list of searches that start with a certain string.
 *
 * @author Matthias Mullie <matthias@mullie.eu>
 */
class FrontendSearchAjaxAutocomplete extends FrontendBaseAJAXAction
{
	/**
	 * Execute the action
	 */
	public function execute()
	{
		// call parent, this will probably add some general CSS/JS or other required files
		parent::execute();

		// get parameters
		$term = SpoonFilter::getPostValue('term', null, '');
		$limit = (int) FrontendModel::getModuleSetting('search', 'autocomplete_num_items', 10);

		// validate
		if($term == '') $this->output(self::BAD_REQUEST, null, 'term-parameter is missing.');

		// get matches
		$matches = FrontendSearchModel::getStartsWith($term, FRONTEND_LANGUAGE, $limit);

		// get search url
		$url = FrontendNavigation::getURLForBlock('search');

		// loop items and set search url
		foreach($matches as &$match) $match['url'] = $url . '?form=search&q=' . $match['term'];

		// output
		$this->output(self::OK, $matches);
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,7 +23,8 @@
 		parent::execute();
 
 		// get parameters
-		$term = SpoonFilter::getPostValue('term', null, '');
+		$searchTerm = SpoonFilter::getPostValue('term', null, '');
+		$term = (SPOON_CHARSET == 'utf-8') ? SpoonFilter::htmlspecialchars($searchTerm) : SpoonFilter::htmlentities($searchTerm);
 		$limit = (int) FrontendModel::getModuleSetting('search', 'autocomplete_num_items', 10);
 
 		// validate
```
