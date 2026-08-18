# CrossVul Fix Pair: Improper Privilege Management in css
**Pair ID:** 2832_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** css
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2832_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```css
Lines 148-188 of the vulnerable file.

}

.label_cpm{
display:block;
}

.form_label{
display:block;
width:180px;
float:left;
}

.form_label_100{
display:block;
width:100px;
float:left;
}

.td_title{
font-weight:bold;
min-width: 150px;
}

ul{
list-style-type:none;
}

.button_menu { outline: 0; margin:0; padding: 1px; text-decoration:none; cursor:pointer; position: relative; text-align: center; }

.title {
  font: bold 160%/100% "Lucida Grande";
  color: #464646;
  margin: 3px 0px 10px 0px;
  padding: 10px;
}

.readme{
  font-family: sans-serif;
  font-size: 9px;
  line-height:15px;
  margin-top: 20px;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,7 +165,7 @@
 
 .td_title{
 font-weight:bold;
-min-width: 150px;
+min-width: 120px;
 }
 
 ul{
@@ -179,6 +179,11 @@
   color: #464646;
   margin: 3px 0px 10px 0px;
   padding: 10px;
+}
+
+.normal {
+  font: normal; "Lucida Grande";
+  color: #464646;
 }
 
 .readme{
@@ -393,3 +398,8 @@
 .hidden {
   display: none;
 }
+
+.no-border {
+  border: none;
+  border-collapse: collapse;
+}
```
