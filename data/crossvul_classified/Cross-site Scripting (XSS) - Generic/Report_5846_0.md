# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5846_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5846_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 469-509 of the vulnerable file.

		}
		$poster_name = format_name($poster['username'], $poster['usergroup'], $poster['displaygroup']);
		if($poster['uid'])
		{
			$onclick = "opener.location.href='".get_profile_link($poster['uid'])."'; return false;";
		}
		$profile_link = build_profile_link($poster_name, $poster['uid'], '_blank', $onclick);
		$numposts += $poster['posts'];
		eval("\$whoposted .= \"".$templates->get("misc_whoposted_poster")."\";");
		$altbg = alt_trow();
	}
	$numposts = my_number_format($numposts);
	eval("\$whop = \"".$templates->get("misc_whoposted")."\";");
	output_page($whop);
}
elseif($mybb->input['action'] == "smilies")
{
	$smilies = '';
	if($mybb->input['popup'])
	{ // make small popup list of smilies
		$editor = addslashes(htmlentities($mybb->input['editor']));
		$e = 1;
		$class = "trow1";
		$smilies = "<tr>";
		$query = $db->simple_select("smilies", "*", "", array('order_by' => 'disporder'));
		while($smilie = $db->fetch_array($query))
		{
			$smilie['insert'] = addslashes($smilie['find']);
			$smilie['find'] = htmlspecialchars_uni($smilie['find']);
			eval("\$smilies .= \"".$templates->get("misc_smilies_popup_smilie")."\";");
			if($e == 2)
			{
				$smilies .= "</tr><tr>";
				$e = 1;
				$class = alt_trow();
			}
			else
			{
				$e = 2;
			}
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -486,7 +486,7 @@
 	$smilies = '';
 	if($mybb->input['popup'])
 	{ // make small popup list of smilies
-		$editor = addslashes(htmlentities($mybb->input['editor']));
+		$editor = preg_replace('#([^a-zA-z0-9_-]+)#', '', $mybb->input['editor']);
 		$e = 1;
 		$class = "trow1";
 		$smilies = "<tr>";
```
