# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3902_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3902_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 76-116 of the vulnerable file.

	assert.equal( jQuery( "<div value='t'></div>" ).attr( "value" ), "t", "Check setting custom attr named 'value' on a div" );
	assert.equal( jQuery( "#form" ).attr( "blah", "blah" ).attr( "blah" ), "blah", "Set non-existent attribute on a form" );
	assert.equal( jQuery( "#foo" ).attr( "height" ), undefined, "Non existent height attribute should return undefined" );

	// [7472] & [3113] (form contains an input with name="action" or name="id")
	extras = jQuery( "<input id='id' name='id' /><input id='name' name='name' /><input id='target' name='target' />" ).appendTo( "#testForm" );
	assert.equal( jQuery( "#form" ).attr( "action", "newformaction" ).attr( "action" ), "newformaction", "Check that action attribute was changed" );
	assert.equal( jQuery( "#testForm" ).attr( "target" ), undefined, "Retrieving target does not equal the input with name=target" );
	assert.equal( jQuery( "#testForm" ).attr( "target", "newTarget" ).attr( "target" ), "newTarget", "Set target successfully on a form" );
	assert.equal( jQuery( "#testForm" ).removeAttr( "id" ).attr( "id" ), undefined, "Retrieving id does not equal the input with name=id after id is removed [#7472]" );

	// Bug #3685 (form contains input with name="name")
	assert.equal( jQuery( "#testForm" ).attr( "name" ), undefined, "Retrieving name does not retrieve input with name=name" );
	extras.remove();

	assert.equal( jQuery( "#text1" ).attr( "maxlength" ), "30", "Check for maxlength attribute" );
	assert.equal( jQuery( "#text1" ).attr( "maxLength" ), "30", "Check for maxLength attribute" );
	assert.equal( jQuery( "#area1" ).attr( "maxLength" ), "30", "Check for maxLength attribute" );

	// using innerHTML in IE causes href attribute to be serialized to the full path
	jQuery( "<a/>" ).attr( {
		"id": "tAnchor5",
		"href": "#5"
	} ).appendTo( "#qunit-fixture" );
	assert.equal( jQuery( "#tAnchor5" ).attr( "href" ), "#5", "Check for non-absolute href (an anchor)" );
	jQuery( "<a id='tAnchor6' href='#5' />" ).appendTo( "#qunit-fixture" );
	assert.equal( jQuery( "#tAnchor5" ).prop( "href" ), jQuery( "#tAnchor6" ).prop( "href" ), "Check for absolute href prop on an anchor" );

	jQuery( "<script type='jquery/test' src='#5' id='scriptSrc'></script>" ).appendTo( "#qunit-fixture" );
	assert.equal( jQuery( "#tAnchor5" ).prop( "href" ), jQuery( "#scriptSrc" ).prop( "src" ), "Check for absolute src prop on a script" );

	// list attribute is readonly by default in browsers that support it
	jQuery( "#list-test" ).attr( "list", "datalist" );
	assert.equal( jQuery( "#list-test" ).attr( "list" ), "datalist", "Check setting list attribute" );

	// Related to [5574] and [5683]
	body = document.body;
	$body = jQuery( body );

	assert.strictEqual( $body.attr( "foo" ), undefined, "Make sure that a non existent attribute returns undefined" );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,12 +93,12 @@
 	assert.equal( jQuery( "#area1" ).attr( "maxLength" ), "30", "Check for maxLength attribute" );
 
 	// using innerHTML in IE causes href attribute to be serialized to the full path
-	jQuery( "<a/>" ).attr( {
+	jQuery( "<a></a>" ).attr( {
 		"id": "tAnchor5",
 		"href": "#5"
 	} ).appendTo( "#qunit-fixture" );
 	assert.equal( jQuery( "#tAnchor5" ).attr( "href" ), "#5", "Check for non-absolute href (an anchor)" );
-	jQuery( "<a id='tAnchor6' href='#5' />" ).appendTo( "#qunit-fixture" );
+	jQuery( "<a id='tAnchor6' href='#5'></a>" ).appendTo( "#qunit-fixture" );
 	assert.equal( jQuery( "#tAnchor5" ).prop( "href" ), jQuery( "#tAnchor6" ).prop( "href" ), "Check for absolute href prop on an anchor" );
 
 	jQuery( "<script type='jquery/test' src='#5' id='scriptSrc'></script>" ).appendTo( "#qunit-fixture" );
@@ -136,7 +136,7 @@
 	assert.equal( $img.attr( "height" ), "53", "Retrieve height attribute on an element with display:none." );
 
 	// Check for style support
-	styleElem = jQuery( "<div/>" ).appendTo( "#qunit-fixture" ).css( {
+	styleElem = jQuery( "<div></div>" ).appendTo( "#qunit-fixture" ).css( {
 		background: "url(UPPERlower.gif)"
 	} );
 	assert.ok( !!~styleElem.attr( "style" ).indexOf( "UPPERlower.gif" ), "Check style attribute getter" );
@@ -158,11 +158,11 @@
 	$a = jQuery( "<a href='#' onclick='something()'>Click</a>" ).appendTo( "#qunit-fixture" );
 	assert.equal( $a.attr( "onclick" ), "something()", "Retrieve ^on attribute without anonymous function wrapper." );
 
-	assert.ok( jQuery( "<div/>" ).attr( "doesntexist" ) === undefined, "Make sure undefined is returned when no attribute is found." );
-	assert.ok( jQuery( "<div/>" ).attr( "title" ) === undefined, "Make sure undefined is returned when no attribute is found." );
-	assert.equal( jQuery( "<div/>" ).attr( "title", "something" ).attr( "title" ), "something", "Set the title attribute." );
+	assert.ok( jQuery( "<div></div>" ).attr( "doesntexist" ) === undefined, "Make sure undefined is returned when no attribute is found." );
+	assert.ok( jQuery( "<div></div>" ).attr( "title" ) === undefined, "Make sure undefined is returned when no attribute is found." );
+	assert.equal( jQuery( "<div></div>" ).attr( "title", "something" ).attr( "title" ), "something", "Set the title attribute." );
 	assert.ok( jQuery().attr( "doesntexist" ) === undefined, "Make sure undefined is returned when no element is there." );
-	assert.equal( jQuery( "<div/>" ).attr( "value" ), undefined, "An unset value on a div returns undefined." );
+	assert.equal( jQuery( "<div></div>" ).attr( "value" ), undefined, "An unset value on a div returns undefined." );
 	assert.strictEqual( jQuery( "<select><option value='property'></option></select>" ).attr( "value" ), undefined, "An unset value on a select returns undefined." );
 
 	$form = jQuery( "#form" ).attr( "enctype", "multipart/form-data" );
@@ -180,7 +180,7 @@
 
 	assert.strictEqual( input.clone( true ).attr( "name", "test" )[ 0 ].name, "test", "Name attribute should be changed on cloned element" );
 
-	div = jQuery( "<div id='tester' />" );
+	div = jQuery( "<div id='tester'></div>" );
 	div.attr( "id" );
 
 	assert.strictEqual( div.clone( true ).attr( "id", "test" )[ 0 ].id, "test", "Id attribute should be changed on cloned element" );
@@ -299,7 +299,7 @@
 	$input = jQuery( "<input type='checkbox'/>" ).attr( "checked", true );
 	assert.equal( $input.prop( "checked" ), true, "Setting checked updates property (verified by .prop)" );
 	assert.equal( $input[ 0 ].checked, true, "Setting checked updates property (verified by native property)" );
-	$input = jQuery( "<option/>" ).attr( "selected", true );
+	$input = jQuery( "<option></option>" ).attr( "selected", true );
 	assert.equal( $input.prop( "selected" ), true, "Setting selected updates property (verified by .prop)" );
 	assert.equal( $input[ 0 ].selected, true, "Setting selected updates property (verified by native property)" );
 
@@ -592,7 +592,7 @@
 	assert.expect( 12 );
 	var $first;
 
-	assert.equal( jQuery( "<div class='hello' />" ).removeAttr( "class" ).attr( "class" ), undefined, "remove class" );
+	assert.equal( jQuery( "<div class='hello'></div>" ).removeAttr( "class" ).attr( "class" ), undefined, "remove class" );
 	assert.equal( jQuery( "#form" ).removeAttr( "id" ).attr( "id" ), undefined, "Remove id" );
 	assert.equal( jQuery( "#foo" ).attr( "style", "position:absolute;" ).removeAttr( "style" ).attr( "style" ), undefined, "Check removing style attribute" );
 	assert.equal( jQuery( "#form" ).attr( "style", "position:absolute;" ).removeAttr( "style" ).attr( "style" ), undefined, "Check removing style attribute on a form" );
@@ -692,7 +692,7 @@
 	assert.equal( jQuery( "#select2" ).prop( "selectedIndex" ), 3, "Check for selectedIndex attribute" );
 	assert.equal( jQuery( "#foo" ).prop( "nodeName" ).toUpperCase(), "DIV", "Check for nodeName attribute" );
 	assert.equal( jQuery( "#foo" ).prop( "tagName" ).toUpperCase(), "DIV", "Check for tagName attribute" );
-	assert.equal( jQuery( "<option/>" ).prop( "selected" ), false, "Check selected attribute on disconnected element." );
+	assert.equal( jQuery( "<option></option>" ).prop( "selected" ), false, "Check selected attribute on disconnected element." );
 
 	assert.equal( jQuery( "#listWithTabIndex" ).prop( "tabindex" ), 5, "Check retrieving tabindex" );
 	jQuery( "#text1" ).prop( "readonly", true );
@@ -837,16 +837,16 @@
 
 	function addOptions( $elem ) {
 		return $elem.append(
-			jQuery( "<option/>" ).val( "a" ).text( "One" ),
-			jQuery( "<option/>" ).val( "b" ).text( "Two" ),
-			jQuery( "<option/>" ).val( "c" ).text( "Three" )
+			jQuery( "<option></option>" ).val( "a" ).text( "One" ),
+			jQuery( "<option></option>" ).val( "b" ).text( "Two" ),
+			jQuery( "<option></option>" ).val( "c" ).text( "Three" )
 		)
 		.find( "[value=a]" ).prop( "selected", true ).end()
 		.find( "[value=c]" ).prop( "selected", true ).end();
 	}
 
 	var $optgroup,
-		$select = jQuery( "<select/>" );
+		$select = jQuery( "<select></select>" );
 
 	// Check select with options
 	addOptions( $select ).appendTo( "#qunit-fixture" );
@@ -856,7 +856,7 @@
 	$select.empty();
 
 	// Check select with optgroup
-	$optgroup = jQuery( "<optgroup/>" );
+	$optgroup = jQuery( "<optgroup></optgroup>" );
 	addOptions( $optgroup ).appendTo( $select );
 	$select.find( "[value=b]" ).prop( "selected", true );
 
@@ -970,7 +970,7 @@
 	assert.equal( $button.val(), "foobar", "Value retrieval on a button does not return innerHTML" );
 	assert.equal( $button.val( "baz" ).html(), "text", "Setting the value does not change innerHTML" );
 
-	assert.equal( jQuery( "<option/>" ).val( "test" ).attr( "value" ), "test", "Setting value sets the value attribute" );
+	assert.equal( jQuery( "<option></option>" ).val( "test" ).attr( "value" ), "test", "Setting value sets the value attribute" );
 } );
 
 QUnit.test( "val() with non-matching values on dropdown list", function( assert ) {
@@ -1029,7 +1029,7 @@
 	assert.equal( document.getElementById( "text1" ).value, "", "Check for modified (via val(null)) value of input element" );
 
 	var j,
-		$select = jQuery( "<select multiple><option value='1'/><option value='2'/></select>" ),
+		$select = jQuery( "<select multiple><option value='1'></option><option value='2'></option></select>" ),
 		$select1 = jQuery( "#select1" );
 
 	$select1.val( valueObj( "3" ) );
@@ -1145,7 +1145,7 @@
 QUnit.test( "select.val(space characters) (gh-2978)", function( assert ) {
 	assert.expect( 37 );
 
-	var $select = jQuery( "<select/>" ).appendTo( "#qunit-fixture" ),
+	var $select = jQuery( "<select></select>" ).appendTo( "#qunit-fixture" ),
 		spaces = {
 			"\\t": {
 				html: "&#09;",
@@ -1230,7 +1230,7 @@
 	j.addClass( valueObj( "asdf" ) );
 	assert.ok( j.hasClass( "asdf" ), "Check node,textnode,comment for addClass" );
 
-	div = jQuery( "<div/>" );
+	div = jQuery( "<div></div>" );
 
 	div.addClass( valueObj( "test" ) );
... (diff truncated)
```
