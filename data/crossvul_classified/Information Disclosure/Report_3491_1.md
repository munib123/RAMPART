# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in html
**Pair ID:** 3491_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3491_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```html
Lines 263-303 of the vulnerable file.

<p>See also the options <a
href="#prefer_uppercase">prefer_uppercase</a> and <a
href="#first_upper">first_upper</a>.</p>

<p id="multiline">"<b>multiline</b>" : [ "begin_re", "end_re"
]<br />
 - if there may be values spread over more than one line this
should define its parsing. Please note that main purpose for this
are lines broken by accident, for example if some editor breaks
longer lines. Example:</p>

<pre>
      Key="value value
      still value
      still value"
</pre>

<p>Then begin regexp is: ([^=]+)="([^"]*) and end regexp is
([^"]"). These are compared at the end so they are the last
possibility. But once we get into this "divided line" by accident,
it becomes greedy, so be carefull to forgotten ". If "multiline" is
not present, this mechanism does not take in effect of course.</p>

<p>See also the option <a
href="#join_multiline">join_multiline</a>.</p>

<div class="notimpl">"names" : [list]<br />
- list of allowed names<br />
- now list may contain only strings. Maybe it will be enriched to
regexps too.</div>

<p>See also the option <a
href="#global_values">global_values</a>.</p>

<h4 id="comments">Comments:</h4>

<p>A list of regular expressions to check. Note that if you combine
all expressions that identify string into one, you will have faster
processing. If you allow comments not starting at the first colunm,
you must add "[ \t]*" before comment regexp. If you want to allow
only comments on single line, prepend ^ before regexp.</p>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -280,7 +280,7 @@
 <p>Then begin regexp is: ([^=]+)="([^"]*) and end regexp is
 ([^"]"). These are compared at the end so they are the last
 possibility. But once we get into this "divided line" by accident,
-it becomes greedy, so be carefull to forgotten ". If "multiline" is
+it becomes greedy, so be carefull to forgotten &quot;. If "multiline" is
 not present, this mechanism does not take in effect of course.</p>
 
 <p>See also the option <a
@@ -473,7 +473,7 @@
         "comments": [ "^[ \t]*#.*$", "#.*", "^[ \t]*$", ],
         "params" : [
             $[
-                "match" : [ "([a-zA-Z0-9_]+)[ \t]*=[ \t]*\"([^\"]*)\"", "%s=\"%s\"" ],
+                "match" : [ "([a-zA-Z0-9_]+)[ \t]*=[ \t]*\"([^\&quot;]*)\"", "%s=\"%s\"" ],
                 "multiline" : [ "([a-zA-Z0-9_]+)[ \t]*=[ \t]*\"([^\"]*)", "([^\"]*)\"", ],
             ],
             $[
@@ -531,6 +531,13 @@
 <tt>.ini.section_type.<i>sectionname</i>.<i>sectionname</i></tt></td>
 <td>identifies type of the section, which is the index of rule this
 section was read by.</td>
+</tr>
+
+<tr>
+<td>
+<tt>.ini.section_private.<i>sectionname</i></tt></td>
+<td>a boolean write-only property for sections corresponding to files.
+If true, the file will not be readable by group and others.</td>
 </tr>
 
 <tr class="notimpl">
@@ -694,7 +701,7 @@
       ],
       "params" : [
         $[
-        "match" : [ "^[ \t]*([^=]*[^ \t=])[ \t]*=[ \t]*(.*[^ \t]|)[ \t]*$" , "%s =       ],
+        "match" : [ "^[ \t]*([^=]*[^ \t=])[ \t]*=[ \t]*(.*[^ \t]|)[ \t]*$" , "%s = %s"   ],
     ],
     ]
   )
```
