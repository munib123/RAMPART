# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1191_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1191_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 521-561 of the vulnerable file.

	/**
	 * Fills in the query variables, which do not exist within the parameter.
	 *
	 * @since 2.1.0
	 * @since 4.4.0 Removed the `comments_popup` public query variable.
	 *
	 * @param array $array Defined query variables.
	 * @return array Complete query variables with undefined ones filled in empty.
	 */
	public function fill_query_vars( $array ) {
		$keys = array(
			'error',
			'm',
			'p',
			'post_parent',
			'subpost',
			'subpost_id',
			'attachment',
			'attachment_id',
			'name',
			'static',
			'pagename',
			'page_id',
			'second',
			'minute',
			'hour',
			'day',
			'monthnum',
			'year',
			'w',
			'category_name',
			'tag',
			'cat',
			'tag_id',
			'author',
			'author_name',
			'feed',
			'tb',
			'paged',
			'meta_key',
			'meta_value',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -538,7 +538,6 @@
 			'attachment',
 			'attachment_id',
 			'name',
-			'static',
 			'pagename',
 			'page_id',
 			'second',
@@ -802,7 +801,7 @@
 			// If year, month, day, hour, minute, and second are set, a single
 			// post is being queried.
 			$this->is_single = true;
-		} elseif ( '' != $qv['static'] || '' != $qv['pagename'] || ! empty( $qv['page_id'] ) ) {
+		} elseif ( '' != $qv['pagename'] || ! empty( $qv['page_id'] ) ) {
 			$this->is_page   = true;
 			$this->is_single = false;
 		} else {
```
