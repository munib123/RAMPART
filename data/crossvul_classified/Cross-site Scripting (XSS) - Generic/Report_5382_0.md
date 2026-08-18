# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 5382_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5382_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 13-53 of the vulnerable file.

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title>{t str=AuditTrail}</title>
  <link rel='stylesheet' type='text/css' href='{$assetPath}/css/dashboard-widget.css'>
  <!--[if IE]>
      <link rel="stylesheet" type="text/css" href="{$assetPath}/css/dashboard-widget-ie.css" />
  <![endif]-->
</head>

<body>

{if $screen == 'enabled'}
    {if $aAuditData|@count > 0}
    <div class="widgetListWrapper widgetContainer">
        <!-- normal view -->
        <ul class="widgetList auditList">
           {foreach from=$aAuditData key=key item=aValue}
            <li>
                <div class="title">
                    <a target="_top" href="userlog-audit-detailed.php?auditId={$aValue.auditid}">
                        {$aValue.desc}
                    </a>
                </div>
                <div>
                    <span class="date">{$aValue.updated|date_format:"%d %b %Y"}</span>
                </div>
            </li>
            {/foreach}
        </ul>
    </div>
    <div><a class="site-link" target="_top" href="{$siteUrl}">{$siteTitle}</a></div>
    {else}
    <div class="widgetListWrapper widgetContainer">
      <ul class="widgetList auditList">
        <li>{$noData}</li>
      </ul>
    </div>
    {/if}
{else}
    <div class="widgetListWrapper widgetContainer">
        <ul class="widgetList auditList">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,7 @@
             <li>
                 <div class="title">
                     <a target="_top" href="userlog-audit-detailed.php?auditId={$aValue.auditid}">
-                        {$aValue.desc}
+                        {$aValue.desc|escape}
                     </a>
                 </div>
                 <div>
```
