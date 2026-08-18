# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 5424_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5424_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 3-36 of the vulnerable file.

+---------------------------------------------------------------------------+
| Revive Adserver                                                           |
| http://www.revive-adserver.com                                            |
|                                                                           |
| Copyright: See the COPYRIGHT.txt file.                                    |
| License: GPLv2 or later, see the LICENSE.txt file.                        |
+---------------------------------------------------------------------------+

-->*}

<div class='dropDown {$cssClass}'>
    <span><span>{$title}</span></span>

    <div class='panel'>
        <div>
            <ul>
    		{section name=linkLoop loop=$aLinks}
        		<li>
        			{if $aLinks[linkLoop].type == 'link'}
            			{if $aLinks[linkLoop].icon}<img src='{$assetPath}/images/{$aLinks[linkLoop].icon}' align='absmiddle' alt=''>{/if}
            			<a href='{$aLinks[linkLoop].url}' {if $aLinks[linkLoop].iconClass}class='inlineIcon {$aLinks[linkLoop].iconClass}'{/if} {if $aLinks[linkLoop].accesskey}accesskey='{$aLinks[linkLoop].accesskey}'{/if} {$aLinks[linkLoop].extraAttr}>{$aLinks[linkLoop].title}</a>
        			{elseif $aLinks[linkLoop].type == 'form'}
            			{if $aLinks[linkLoop].icon}<img src='{$assetPath}/images/{$aLinks[linkLoop].icon}' align='absmiddle' alt=''>{/if}
            			<label {if $aLinks[linkLoop].iconClass}class='inlineIcon {$aLinks[linkLoop].iconClass}'{/if}>{$aLinks[linkLoop].title}</label>
               			{$aLinks[linkLoop].form}
        			{/if}
        		</li>
    		{/section}
            </ul>
        </div>
    </div>

    <div class='mask'></div>
</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,7 @@
         		<li>
         			{if $aLinks[linkLoop].type == 'link'}
             			{if $aLinks[linkLoop].icon}<img src='{$assetPath}/images/{$aLinks[linkLoop].icon}' align='absmiddle' alt=''>{/if}
-            			<a href='{$aLinks[linkLoop].url}' {if $aLinks[linkLoop].iconClass}class='inlineIcon {$aLinks[linkLoop].iconClass}'{/if} {if $aLinks[linkLoop].accesskey}accesskey='{$aLinks[linkLoop].accesskey}'{/if} {$aLinks[linkLoop].extraAttr}>{$aLinks[linkLoop].title}</a>
+                        <a href='{$aLinks[linkLoop].url|escape}' {if $aLinks[linkLoop].iconClass}class='inlineIcon {$aLinks[linkLoop].iconClass}'{/if} {if $aLinks[linkLoop].accesskey}accesskey='{$aLinks[linkLoop].accesskey}'{/if} {$aLinks[linkLoop].extraAttr}>{$aLinks[linkLoop].title}</a>
         			{elseif $aLinks[linkLoop].type == 'form'}
             			{if $aLinks[linkLoop].icon}<img src='{$assetPath}/images/{$aLinks[linkLoop].icon}' align='absmiddle' alt=''>{/if}
             			<label {if $aLinks[linkLoop].iconClass}class='inlineIcon {$aLinks[linkLoop].iconClass}'{/if}>{$aLinks[linkLoop].title}</label>
```
