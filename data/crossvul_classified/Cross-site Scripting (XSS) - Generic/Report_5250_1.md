# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5250_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5250_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 409-449 of the vulnerable file.

			"ui-dialog-titlebar", "ui-widget-header ui-helper-clearfix" );
		this._on( this.uiDialogTitlebar, {
			mousedown: function( event ) {

				// Don't prevent click on close button (#8838)
				// Focusing a dialog that is partially scrolled out of view
				// causes the browser to scroll it into view, preventing the click event
				if ( !$( event.target ).closest( ".ui-dialog-titlebar-close" ) ) {

					// Dialog isn't getting focus when dragging (#8063)
					this.uiDialog.trigger( "focus" );
				}
			}
		} );

		// Support: IE
		// Use type="button" to prevent enter keypresses in textboxes from closing the
		// dialog in IE (#9312)
		this.uiDialogTitlebarClose = $( "<button type='button'></button>" )
			.button( {
				label: this.options.closeText,
				icon: "ui-icon-closethick",
				showLabel: false
			} )
			.appendTo( this.uiDialogTitlebar );

		this._addClass( this.uiDialogTitlebarClose, "ui-dialog-titlebar-close" );
		this._on( this.uiDialogTitlebarClose, {
			click: function( event ) {
				event.preventDefault();
				this.close( event );
			}
		} );

		uiDialogTitle = $( "<span>" ).uniqueId().prependTo( this.uiDialogTitlebar );
		this._addClass( uiDialogTitle, "ui-dialog-title" );
		this._title( uiDialogTitle );

		this.uiDialogTitlebar.prependTo( this.uiDialog );

		this.uiDialog.attr( {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -426,7 +426,7 @@
 		// dialog in IE (#9312)
 		this.uiDialogTitlebarClose = $( "<button type='button'></button>" )
 			.button( {
-				label: this.options.closeText,
+				label: $( "<a>" ).text( this.options.closeText ).html(),
 				icon: "ui-icon-closethick",
 				showLabel: false
 			} )
@@ -715,7 +715,7 @@
 			this.uiDialogTitlebarClose.button( {
 
 				// Ensure that we always pass a string
-				label: "" + value
+				label: $( "<a>" ).text( "" + this.options.closeText ).html()
 			} );
 		}
 
```
