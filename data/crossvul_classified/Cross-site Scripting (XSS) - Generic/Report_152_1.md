# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 152_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `152_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-22 of the vulnerable file.

<div class="wity-app wity-app-search wity-action-form">
	<h1>{lang Research} {if !empty({$query})}<strong>"{$query}"</strong>{/if}</h1>

	<form class="search-form" action="/search" method="get">
		<p class="input-group research">
			<input class="form-control" type="text" name="query" placeholder="{lang Search}" value="{if !empty({$query})}{$query}{/if}" />
			<span class="input-group-btn">
				<button class="btn btn-default" type="submit"><span class="glyphicon glyphicon-search"></span></button>
			</span>
		</p>
	</form>

{for $app, $app_result in $results}
	{if !empty({$app_result})}
	<h2>{$app|ucwords}</h2>
	<dl>
		{for $result in $app_result}
		<dt>
			<a href="{$result.url}">{$result.title}</a><br />
			{lang Address:} {$result.url}
		</dt>
		<dd>{$result.description}</dd>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,9 +1,9 @@
 <div class="wity-app wity-app-search wity-action-form">
-	<h1>{lang Research} {if !empty({$query})}<strong>"{$query}"</strong>{/if}</h1>
+	<h1>{lang Research} {if !empty({$query})}<strong>"{!$query!}"</strong>{/if}</h1>
 
 	<form class="search-form" action="/search" method="get">
 		<p class="input-group research">
-			<input class="form-control" type="text" name="query" placeholder="{lang Search}" value="{if !empty({$query})}{$query}{/if}" />
+			<input class="form-control" type="text" name="query" placeholder="{lang Search}" value="{if !empty({$query})}{!$query!}{/if}" />
 			<span class="input-group-btn">
 				<button class="btn btn-default" type="submit"><span class="glyphicon glyphicon-search"></span></button>
 			</span>
```
