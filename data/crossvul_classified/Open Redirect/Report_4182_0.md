# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in html
**Pair ID:** 4182_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4182_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```html
Lines 12-51 of the vulnerable file.

A string with numbers in it: {types.aStringWithNumbers as integer}
Ditto, with type name stored in variable: {types.aStringWithNumbers as types.typeNameInteger}
A comma-separated value iterated as array:
<f:for each="{types.csv as array}" as="arrayMember">	- {arrayMember}
</f:for>
<!-- Dynamic string: changing "dynamic1" to "dynamic2" reads other string -->
String variable name with dynamic1 part: {stringwith{dynamic1}part}.
String variable name with dynamic2 part: {stringwith{dynamic2}part}.
Output of variable whose name is stored in a variable: {{dynamicVariableName}}

<!-- Dynamic array: changing "dynanic1" to "dynamic2" reads other array member -->
Array member in $array[$dynamic1]: {array.{dynamic1}}
Array member in $array[$dynamic2]: {array.{dynamic2}}

<!-- Numerically prefixed variables -->
Direct access of numeric prefixed variable: {123numericprefix}
<f:alias map="{mappedNumericPrefix: 123numericprefix}">Aliased access of numeric prefixed variable: {mappedNumericPrefix}</f:alias>

<!-- Passing arguments to sections/partials -->
<f:render section="Secondary" arguments="{
	myVariable: 'Nice string',
	array: {
		baz: 42,
		foobar: '<b>Unescaped string</b>',
		printf: 'Formatted string, value: %s',
		xyz: '{
			foobar: \'Escaped sub-string\'
		}'
	}
}"/>

</f:section>

<f:section name="Secondary">
Received $array.foobar with value {array.foobar -> f:format.raw()} (same using "value" argument: {f:format.raw(value: array.foobar)})
Received $array.printf with formatted string {array.printf -> f:format.printf(arguments: {0: 'formatted'})}
Received $array.baz with value {array.baz}
Received $array.xyz.foobar with value {array.xyz.foobar}
Received $myVariable with value {myVariable}
</f:section>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
 
 <!-- Passing arguments to sections/partials -->
 <f:render section="Secondary" arguments="{
+    ternaryCheck: 1,
 	myVariable: 'Nice string',
 	array: {
 		baz: 42,
@@ -43,6 +44,8 @@
 </f:section>
 
 <f:section name="Secondary">
+Escaped ternary expression: {ternaryCheck ? array.foobar : array.foobar}
+Escaped cast expression: {array.foobar as string}
 Received $array.foobar with value {array.foobar -> f:format.raw()} (same using "value" argument: {f:format.raw(value: array.foobar)})
 Received $array.printf with formatted string {array.printf -> f:format.printf(arguments: {0: 'formatted'})}
 Received $array.baz with value {array.baz}
```
