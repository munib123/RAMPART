# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3778_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3778_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 5-45 of the vulnerable file.

 *
 * For the full copyright and license information, please view the license
 * file that was distributed with this source code.
 */

/**
 * This is the save-action, it will save the searched term in the statistics
 *
 * @author Matthias Mullie <matthias@mullie.eu>
 */
class FrontendSearchAjaxSave extends FrontendBaseAJAXAction
{
	/**
	 * Execute the action
	 */
	public function execute()
	{
		parent::execute();

		// get parameters
		$term = SpoonFilter::getPostValue('term', null, '');

		// validate
		if($term == '') $this->output(self::BAD_REQUEST, null, 'term-parameter is missing.');

		// previous search result
		$previousTerm = SpoonSession::exists('searchTerm') ? SpoonSession::get('searchTerm') : '';
		SpoonSession::set('searchTerm', '');

		// save this term?
		if($previousTerm != $term)
		{
			// format data
			$this->statistics = array();
			$this->statistics['term'] = $term;
			$this->statistics['language'] = FRONTEND_LANGUAGE;
			$this->statistics['time'] = FrontendModel::getUTCDate();
			$this->statistics['data'] = serialize(array('server' => $_SERVER));
			$this->statistics['num_results'] = FrontendSearchModel::getTotal($term);

			// save data
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,7 +22,8 @@
 		parent::execute();
 
 		// get parameters
-		$term = SpoonFilter::getPostValue('term', null, '');
+		$searchTerm = SpoonFilter::getPostValue('term', null, '');
+		$term = (SPOON_CHARSET == 'utf-8') ? SpoonFilter::htmlspecialchars($searchTerm) : SpoonFilter::htmlentities($searchTerm);
 
 		// validate
 		if($term == '') $this->output(self::BAD_REQUEST, null, 'term-parameter is missing.');
```
