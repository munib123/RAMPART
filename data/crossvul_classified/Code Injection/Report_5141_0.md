# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5141_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5141_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 483-523 of the vulnerable file.


	$context['onimg'] = $settings['images_url'] . '/bbc/bbc_bg.png';
	$context['offimg'] = $settings['images_url'] . '/bbc/bbc_hoverbg.png';

	$context['page_title'] = 'Anyone know what time it is?';
	$context['linktree'][] = array(
			'url' => $scripturl . '?action=clock',
			'name' => 'Clock',
	);
	$context['robot_no_index'] = true;

	$omfg = isset($_REQUEST['omfg']);
	$bcd = !isset($_REQUEST['rb']) && !isset($_REQUEST['omfg']) && !isset($_REQUEST['time']);

	loadTemplate('Calendar');

	if ($bcd)
	{
		$context['sub_template'] = 'bcd';
		$context['linktree'][] = array('url' => $scripturl . '?action=clock;bcd', 'name' => 'BCD');
		$context['clockicons'] = unserialize(base64_decode('YTo2OntzOjI6ImgxIjthOjI6e2k6MDtpOjI7aToxO2k6MTt9czoyOiJoMiI7YTo0OntpOjA7aTo4O2k6MTtpOjQ7aToyO2k6MjtpOjM7aToxO31zOjI6Im0xIjthOjM6e2k6MDtpOjQ7aToxO2k6MjtpOjI7aToxO31zOjI6Im0yIjthOjQ6e2k6MDtpOjg7aToxO2k6NDtpOjI7aToyO2k6MztpOjE7fXM6MjoiczEiO2E6Mzp7aTowO2k6NDtpOjE7aToyO2k6MjtpOjE7fXM6MjoiczIiO2E6NDp7aTowO2k6ODtpOjE7aTo0O2k6MjtpOjI7aTozO2k6MTt9fQ=='));
	}
	elseif (!$omfg && !isset($_REQUEST['time']))
	{
		$context['sub_template'] = 'hms';
		$context['linktree'][] = array('url' => $scripturl . '?action=clock', 'name' => 'Binary');
		$context['clockicons'] = unserialize(base64_decode('YTozOntzOjE6ImgiO2E6NTp7aTowO2k6MTY7aToxO2k6ODtpOjI7aTo0O2k6MztpOjI7aTo0O2k6MTt9czoxOiJtIjthOjY6e2k6MDtpOjMyO2k6MTtpOjE2O2k6MjtpOjg7aTozO2k6NDtpOjQ7aToyO2k6NTtpOjE7fXM6MToicyI7YTo2OntpOjA7aTozMjtpOjE7aToxNjtpOjI7aTo4O2k6MztpOjQ7aTo0O2k6MjtpOjU7aToxO319'));
	}
	elseif ($omfg)
	{
		$context['sub_template'] = 'omfg';
		$context['linktree'][] = array('url' => $scripturl . '?action=clock;omfg', 'name' => 'OMFG');
		$context['clockicons'] = unserialize(base64_decode('YTo2OntzOjQ6InllYXIiO2E6Nzp7aTowO2k6NjQ7aToxO2k6MzI7aToyO2k6MTY7aTozO2k6ODtpOjQ7aTo0O2k6NTtpOjI7aTo2O2k6MTt9czo1OiJtb250aCI7YTo0OntpOjA7aTo4O2k6MTtpOjQ7aToyO2k6MjtpOjM7aToxO31zOjM6ImRheSI7YTo1OntpOjA7aToxNjtpOjE7aTo4O2k6MjtpOjQ7aTozO2k6MjtpOjQ7aToxO31zOjQ6ImhvdXIiO2E6NTp7aTowO2k6MTY7aToxO2k6ODtpOjI7aTo0O2k6MztpOjI7aTo0O2k6MTt9czozOiJtaW4iO2E6Njp7aTowO2k6MzI7aToxO2k6MTY7aToyO2k6ODtpOjM7aTo0O2k6NDtpOjI7aTo1O2k6MTt9czozOiJzZWMiO2E6Njp7aTowO2k6MzI7aToxO2k6MTY7aToyO2k6ODtpOjM7aTo0O2k6NDtpOjI7aTo1O2k6MTt9fQ=='));
	}
	elseif (isset($_REQUEST['time']))
	{
		$context['sub_template'] = 'thetime';
		$time = getdate($_REQUEST['time'] == 'now' ? time() : (int) $_REQUEST['time']);
		$year = $time['year'] % 100;
		$month = $time['mon'];
		$day = $time['mday'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -500,19 +500,19 @@
 	{
 		$context['sub_template'] = 'bcd';
 		$context['linktree'][] = array('url' => $scripturl . '?action=clock;bcd', 'name' => 'BCD');
-		$context['clockicons'] = unserialize(base64_decode('YTo2OntzOjI6ImgxIjthOjI6e2k6MDtpOjI7aToxO2k6MTt9czoyOiJoMiI7YTo0OntpOjA7aTo4O2k6MTtpOjQ7aToyO2k6MjtpOjM7aToxO31zOjI6Im0xIjthOjM6e2k6MDtpOjQ7aToxO2k6MjtpOjI7aToxO31zOjI6Im0yIjthOjQ6e2k6MDtpOjg7aToxO2k6NDtpOjI7aToyO2k6MztpOjE7fXM6MjoiczEiO2E6Mzp7aTowO2k6NDtpOjE7aToyO2k6MjtpOjE7fXM6MjoiczIiO2E6NDp7aTowO2k6ODtpOjE7aTo0O2k6MjtpOjI7aTozO2k6MTt9fQ=='));
+		$context['clockicons'] = safe_unserialize(base64_decode('YTo2OntzOjI6ImgxIjthOjI6e2k6MDtpOjI7aToxO2k6MTt9czoyOiJoMiI7YTo0OntpOjA7aTo4O2k6MTtpOjQ7aToyO2k6MjtpOjM7aToxO31zOjI6Im0xIjthOjM6e2k6MDtpOjQ7aToxO2k6MjtpOjI7aToxO31zOjI6Im0yIjthOjQ6e2k6MDtpOjg7aToxO2k6NDtpOjI7aToyO2k6MztpOjE7fXM6MjoiczEiO2E6Mzp7aTowO2k6NDtpOjE7aToyO2k6MjtpOjE7fXM6MjoiczIiO2E6NDp7aTowO2k6ODtpOjE7aTo0O2k6MjtpOjI7aTozO2k6MTt9fQ=='));
 	}
 	elseif (!$omfg && !isset($_REQUEST['time']))
 	{
 		$context['sub_template'] = 'hms';
 		$context['linktree'][] = array('url' => $scripturl . '?action=clock', 'name' => 'Binary');
-		$context['clockicons'] = unserialize(base64_decode('YTozOntzOjE6ImgiO2E6NTp7aTowO2k6MTY7aToxO2k6ODtpOjI7aTo0O2k6MztpOjI7aTo0O2k6MTt9czoxOiJtIjthOjY6e2k6MDtpOjMyO2k6MTtpOjE2O2k6MjtpOjg7aTozO2k6NDtpOjQ7aToyO2k6NTtpOjE7fXM6MToicyI7YTo2OntpOjA7aTozMjtpOjE7aToxNjtpOjI7aTo4O2k6MztpOjQ7aTo0O2k6MjtpOjU7aToxO319'));
+		$context['clockicons'] = safe_unserialize(base64_decode('YTozOntzOjE6ImgiO2E6NTp7aTowO2k6MTY7aToxO2k6ODtpOjI7aTo0O2k6MztpOjI7aTo0O2k6MTt9czoxOiJtIjthOjY6e2k6MDtpOjMyO2k6MTtpOjE2O2k6MjtpOjg7aTozO2k6NDtpOjQ7aToyO2k6NTtpOjE7fXM6MToicyI7YTo2OntpOjA7aTozMjtpOjE7aToxNjtpOjI7aTo4O2k6MztpOjQ7aTo0O2k6MjtpOjU7aToxO319'));
 	}
 	elseif ($omfg)
 	{
 		$context['sub_template'] = 'omfg';
 		$context['linktree'][] = array('url' => $scripturl . '?action=clock;omfg', 'name' => 'OMFG');
-		$context['clockicons'] = unserialize(base64_decode('YTo2OntzOjQ6InllYXIiO2E6Nzp7aTowO2k6NjQ7aToxO2k6MzI7aToyO2k6MTY7aTozO2k6ODtpOjQ7aTo0O2k6NTtpOjI7aTo2O2k6MTt9czo1OiJtb250aCI7YTo0OntpOjA7aTo4O2k6MTtpOjQ7aToyO2k6MjtpOjM7aToxO31zOjM6ImRheSI7YTo1OntpOjA7aToxNjtpOjE7aTo4O2k6MjtpOjQ7aTozO2k6MjtpOjQ7aToxO31zOjQ6ImhvdXIiO2E6NTp7aTowO2k6MTY7aToxO2k6ODtpOjI7aTo0O2k6MztpOjI7aTo0O2k6MTt9czozOiJtaW4iO2E6Njp7aTowO2k6MzI7aToxO2k6MTY7aToyO2k6ODtpOjM7aTo0O2k6NDtpOjI7aTo1O2k6MTt9czozOiJzZWMiO2E6Njp7aTowO2k6MzI7aToxO2k6MTY7aToyO2k6ODtpOjM7aTo0O2k6NDtpOjI7aTo1O2k6MTt9fQ=='));
+		$context['clockicons'] = safe_unserialize(base64_decode('YTo2OntzOjQ6InllYXIiO2E6Nzp7aTowO2k6NjQ7aToxO2k6MzI7aToyO2k6MTY7aTozO2k6ODtpOjQ7aTo0O2k6NTtpOjI7aTo2O2k6MTt9czo1OiJtb250aCI7YTo0OntpOjA7aTo4O2k6MTtpOjQ7aToyO2k6MjtpOjM7aToxO31zOjM6ImRheSI7YTo1OntpOjA7aToxNjtpOjE7aTo4O2k6MjtpOjQ7aTozO2k6MjtpOjQ7aToxO31zOjQ6ImhvdXIiO2E6NTp7aTowO2k6MTY7aToxO2k6ODtpOjI7aTo0O2k6MztpOjI7aTo0O2k6MTt9czozOiJtaW4iO2E6Njp7aTowO2k6MzI7aToxO2k6MTY7aToyO2k6ODtpOjM7aTo0O2k6NDtpOjI7aTo1O2k6MTt9czozOiJzZWMiO2E6Njp7aTowO2k6MzI7aToxO2k6MTY7aToyO2k6ODtpOjM7aTo0O2k6NDtpOjI7aTo1O2k6MTt9fQ=='));
 	}
 	elseif (isset($_REQUEST['time']))
 	{
```
