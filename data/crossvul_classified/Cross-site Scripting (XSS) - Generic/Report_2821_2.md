# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2821_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2821_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 62-102 of the vulnerable file.

	 */
	init: function() {
		this._super.apply(this, arguments);

		var event = this;

		// Main container
		this.div = jQuery(document.createElement("div"))
			.addClass("calendar_calEvent")
			.addClass(this.options.class)
			.css('width',this.options.width)
			.on('mouseenter', function() {
				// Bind actions on first mouseover for faster creation
				if(event._need_actions_linked)
				{
					event._copy_parent_actions();
				}
				// Tooltip
				if(!event._tooltipElem)
				{
					event.set_statustext(event._tooltip());
					return event.div.trigger('mouseenter');
				}
				// Hacky to remove egw's tooltip border and let the mouse in
				window.setTimeout(function() {
					jQuery('body .egw_tooltip')
						.css('border','none')
						.on('mouseenter', function() {
							event.div.off('mouseleave.tooltip');
							jQuery('body.egw_tooltip').remove();
							jQuery('body').append(this);
							jQuery(this).stop(true).fadeTo(400, 1)
								.on('mouseleave', function() {
									jQuery(this).fadeOut('400', function() {
										jQuery(this).remove();
										// Set up to work again
										event.set_statustext(event._tooltip());
									});
								});
						});

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,6 +79,7 @@
 				// Tooltip
 				if(!event._tooltipElem)
 				{
+					event.options.statustext_html = true;
 					event.set_statustext(event._tooltip());
 					return event.div.trigger('mouseenter');
 				}
@@ -209,7 +210,7 @@
 			{
 				parent._out_of_view();
 			}
-			
+
 			// This should now cease to exist, as new events have been created
 			this.free();
 			return;
@@ -521,7 +522,7 @@
 				'<span class="calendar_calEventTitle">'+egw.htmlspecialchars(this.options.value.title)+'</span><br>'+
 				egw.htmlspecialchars(this.options.value.description)+'</p>'+
 				'<p style="margin: 2px 0px;">'+times+'</p>'+
-				(this.options.value.location ? '<p><span class="calendar_calEventLabel">'+this.egw().lang('Location') + '</span>:' + 
+				(this.options.value.location ? '<p><span class="calendar_calEventLabel">'+this.egw().lang('Location') + '</span>:' +
 				egw.htmlspecialchars(this.options.value.location)+'</p>' : '')+
 				(cat_label ? '<p><span class="calendar_calEventLabel">'+this.egw().lang('Category') + '</span>:' + cat_label +'</p>' : '')+
 				'<p><span class="calendar_calEventLabel">'+this.egw().lang('Participants')+'</span>:<br />'+
@@ -541,7 +542,7 @@
 		{
 			return '';
 		}
-		
+
 		var participant_status = {A: 0, R: 0, T: 0, U: 0, D: 0};
 		var status_label = {A: 'accepted', R: 'rejected', T: 'tentative', U: 'unknown', D: 'delegated'};
 		var participant_summary = Object.keys(this.options.value.participants).length + ' ' + this.egw().lang('Participants')+': ';
@@ -914,7 +915,7 @@
 			}
 		}
 	},
-	
+
 	/**
 	 * Link the actions to the DOM nodes / widget bits.
 	 *
```
