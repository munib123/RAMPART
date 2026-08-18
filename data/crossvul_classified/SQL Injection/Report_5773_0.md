# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5773_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5773_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 182-222 of the vulnerable file.

		{
			$flag_private = 1;
		}

		if (!$flag_private && cot_auth('forums', $forum_id, 'R'))
		{
			$items[$i]['title'] = $row['fp_postername']." - ".$topic_title;
			$items[$i]['description'] = cot_parse_post_text($row['fp_text']);
			$url = cot_url('forums', "m=posts&p=$post_id", "#$post_id", true);
			$items[$i]['link'] = (strpos($url, '://') === false) ? COT_ABSOLUTE_URL . $url : $url;
			$items[$i]['pubDate'] = cot_date('r', $row['fp_creation']);
		}

		$i++;
	}
}
elseif ($default_mode)
{
	require_once cot_incfile('page', 'module');

	if (!empty($c))
	{
		$mtch = $structure['page'][$c]['path'].".";
		$mtchlen = mb_strlen($mtch);
		$catsub = array();
		$catsub[] = $c;

		foreach ($structure['page'] as $i => $x)
		{
			if (mb_substr($x['path'], 0, $mtchlen) == $mtch)
			{
				$catsub[] = $i;
			}
		}

		$sql = $db->query("SELECT p.*, u.* FROM $db_pages AS p
				LEFT JOIN $db_users AS u ON p.page_ownerid = u.user_id
			WHERE page_state=0 AND page_begin <= {$sys['now']} AND (page_expire = 0 OR page_expire > {$sys['now']}) AND page_cat NOT LIKE 'system' AND page_cat IN ('".implode("','", $catsub)."')
			ORDER BY page_date DESC LIMIT ".$cfg['rss']['rss_maxitems']);
	}
	else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -199,7 +199,7 @@
 {
 	require_once cot_incfile('page', 'module');
 
-	if (!empty($c))
+	if (!empty($c) && isset($structure['page'][$c]))
 	{
 		$mtch = $structure['page'][$c]['path'].".";
 		$mtchlen = mb_strlen($mtch);
```
