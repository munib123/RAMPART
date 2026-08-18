# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5141_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5141_4`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 552-592 of the vulnerable file.

}

/**
 * Fixes corrupted serialized strings after a character set conversion.
 */
function fix_serialized_columns()
{
	global $smcFunc;

	$request = $smcFunc['db_query']('', '
		SELECT id_action, extra
		FROM {db_prefix}log_actions
		WHERE action IN ({string:remove}, {string:delete})',
		array(
			'remove' => 'remove',
			'delete' => 'delete',
		)
	);
	while ($row = $smcFunc['db_fetch_assoc']($request))
	{
		if (@unserialize($row['extra']) === false && preg_match('~^(a:3:{s:5:"topic";i:\d+;s:7:"subject";s:)(\d+):"(.+)"(;s:6:"member";s:5:"\d+";})$~', $row['extra'], $matches) === 1)
			$smcFunc['db_query']('', '
				UPDATE {db_prefix}log_actions
				SET extra = {string:extra}
				WHERE id_action = {int:current_action}',
				array(
					'current_action' => $row['id_action'],
					'extra' => $matches[1] . strlen($matches[3]) . ':"' . $matches[3] . '"' . $matches[4],
				)
			);
	}
	$smcFunc['db_free_result']($request);

	// Refresh some cached data.
	updateSettings(array(
		'memberlist_updated' => time(),
	));

}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -569,7 +569,7 @@
 	);
 	while ($row = $smcFunc['db_fetch_assoc']($request))
 	{
-		if (@unserialize($row['extra']) === false && preg_match('~^(a:3:{s:5:"topic";i:\d+;s:7:"subject";s:)(\d+):"(.+)"(;s:6:"member";s:5:"\d+";})$~', $row['extra'], $matches) === 1)
+		if (safe_unserialize($row['extra']) === false && preg_match('~^(a:3:{s:5:"topic";i:\d+;s:7:"subject";s:)(\d+):"(.+)"(;s:6:"member";s:5:"\d+";})$~', $row['extra'], $matches) === 1)
 			$smcFunc['db_query']('', '
 				UPDATE {db_prefix}log_actions
 				SET extra = {string:extra}
```
