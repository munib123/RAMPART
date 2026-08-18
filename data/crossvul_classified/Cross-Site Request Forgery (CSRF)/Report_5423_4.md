# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in html
**Pair ID:** 5423_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5423_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```html
Lines 1-36 of the vulnerable file.

{*<!--

+---------------------------------------------------------------------------+
| Revive Adserver                                                           |
| http://www.revive-adserver.com                                            |
|                                                                           |
| Copyright: See the COPYRIGHT.txt file.                                    |
| License: GPLv2 or later, see the LICENSE.txt file.                        |
+---------------------------------------------------------------------------+

-->*}
{view_before_content}

<form id="zoneLinkingForm">
<div id="campaign-zone" class="new-form">
  <input id="advertiser-id" type="hidden" value="{$advertiserId}" />
  <input id="campaign-id" type="hidden" value="{$campaignId}" />

  <div id="filters">
    <div id="filters-available">
      <h3 class="filter-panel-title">{t str=AvailableZones}</h3>
      <div class="filter-panel">
	      <div class="bg-left"></div>
	      <div class="bg-right"></div>

	      <div class="filter-content">
          <div id="status-available">&nbsp;</div>
	        {include file=campaign-zone-panel-filters.html
	                 panelId=available categories=$aCategories}
	      </div>
	      &nbsp;
	    </div>
    </div>

    <div id="filters-linked">
      <h3 class="filter-panel-title">{t str=LinkedZones}</h3>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,7 @@
 
 <form id="zoneLinkingForm">
 <div id="campaign-zone" class="new-form">
+  <input id="csrf-token" type="hidden" value="{$csrfToken|escape}" />
   <input id="advertiser-id" type="hidden" value="{$advertiserId}" />
   <input id="campaign-id" type="hidden" value="{$campaignId}" />
 
@@ -213,6 +214,7 @@
     }
 
     var postData = {
+      "token": $("#csrf-token").val(),
       "clientid": $("#advertiser-id").val(),
       "campaignid": $("#campaign-id").val(),
       "text-linked": quickSearchLinked,
@@ -238,6 +240,9 @@
           updatePanel(data, "available");
           updatePanel(data, "linked");
 
+          // Refresh token
+          $("#csrf-token").val(extractPart(data, "value", "token"));
+
 	        $("#linking-status").html(extractPart(data, "info", "result")).stop().show().css("opacity", "1");
 	        if (window.linkingTimout) {
 	          window.linkingTimout.clearTimeout();
```
