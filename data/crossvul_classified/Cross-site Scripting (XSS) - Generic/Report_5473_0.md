# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 5473_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5473_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 5-45 of the vulnerable file.

          <div class="icon"></div>
          <div class="body">
            {if $showSkipSsoForm}
				<div id="skipsso-form-container" style="margin-left:10px">
				<p>
				We were unable to reach the OpenX Market account registration service at this time.
				In order to continue with the installation process, you may continue without registering 
				or you may try registering again on the form below.
				<br/><br/>
				Note: if you continue without registering, you will need to register with OpenX later in 
				order to be able to serve ads from OpenX Market.
				{include file=$oaTemplateDir|cat:'form/form.html' form=$skipSsoForm}
				
				<a id='moreDetails'>More details about the error &#8250;</a>
				<br/><br/>
				</p>
				</div>
			{/if}
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

{if $showSkipSsoForm}
{literal}
<script type="text/javascript">
$(document).ready(function() {
	$('#errorMessages').hide(); 
	$('#moreDetails').click( function() {
		$('#errorMessages').toggle(); 
	});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,7 +22,7 @@
 			{/if}
 			<span id='errorMessages'>
             {foreach from=$aMessages.error item=error name=messagesLoop}
-              {$error} {if !$smarty.foreach.messagesLoop.last}<br/>{/if}
+              {$error|escape} {if !$smarty.foreach.messagesLoop.last}<br/>{/if}
             {/foreach}
             </span>
           </div>
```
