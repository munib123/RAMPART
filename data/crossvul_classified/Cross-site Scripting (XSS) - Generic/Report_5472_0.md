# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 5472_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5472_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-20 of the vulnerable file.

{if $aMessages.error || $forceRender}
    <div class="messagePlaceholder messagePlaceholderStatic {if $class}{$class}{/if}" {if $id}id={$id}{/if}>
      <div class="message localMessage">
        <div class="panel error">
          <div class="icon"></div>
          <div class="body">
			<span id='errorMessages'>
            {foreach from=$aMessages.error item=error name=messagesLoop}
              {$error} {if !$smarty.foreach.messagesLoop.last}<br/>{/if}
            {/foreach}
            </span>
          </div>
          <div class="topleft"></div>
          <div class="topright"></div>
          <div class="bottomleft"></div>
          <div class="bottomright"></div>
        </div>
      </div>
    </div>    
{/if}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
           <div class="body">
 			<span id='errorMessages'>
             {foreach from=$aMessages.error item=error name=messagesLoop}
-              {$error} {if !$smarty.foreach.messagesLoop.last}<br/>{/if}
+              {$error|escape} {if !$smarty.foreach.messagesLoop.last}<br/>{/if}
             {/foreach}
             </span>
           </div>
```
