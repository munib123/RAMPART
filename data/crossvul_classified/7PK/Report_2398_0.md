# CrossVul Fix Pair: 7PK in html
**Pair ID:** 2398_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2398_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```html
Lines 44-84 of the vulnerable file.

 <img src="http://ci.jenkins-ci.org/images/16x16/health-40to59.gif" width="16" height="16"
  alt="Cloudy"> = I don't recommend it. <br>
 <img src="http://ci.jenkins-ci.org/images/16x16/health-00to19.gif" width="16" height="16"
  alt="Lightning"> = I tried it but rolled back to a previous version. <br>
View ratings below, and click one of the icons next to your version to provide your input.
</div>

<a href="" onClick="document.getElementById('trunk').style.display=document.getElementById('rc').style.display='block';return false">
Upcoming changes</a>
<a href="" style="padding-left:3em" onClick="return loaddata(this)">Community ratings</a>

<!-- Record your changes in the trunk here. -->
<div id="trunk" style="display:none"><!--=TRUNK-BEGIN=-->
<ul class=image>
  <li class=rfe>
    Bumping up JNA to 4.10. This is potentially a breaking change for plugins that depend on JNA 3.x
    (<a href="https://issues.jenkins-ci.org/browse/JENKINS-24521">issue 24521</a>)
  <li class=bug>
    Prevent empty file creation if file parameter is left empty.
    (<a href="https://issues.jenkins-ci.org/browse/JENKINS-3539">issue 3539</a>)
</ul>
</div><!--=TRUNK-END=-->

<!-- these changes are controlled by the release process. DO NOT MODIFY -->
<div id="rc" style="display:none;"><!--=BEGIN=-->
<h3><a name=v1.585>What's new in 1.585</a> <!--=DATE=--></h3>
<ul class=image>
  <li class=bug>
    Build health computed repeatedly for a single Weather column cell.
    (<a href="https://issues.jenkins-ci.org/browse/JENKINS-25074">issue 25074</a>)
  <li class=rfe>
    Missing workspace page should use 404 status code.
    (<a href="https://issues.jenkins-ci.org/browse/JENKINS-10450">issue 10450</a>)
  <li class=bug>
    Fixed memory leak occurring on pages producing incremental output with a progress bar.
    (<a href="https://issues.jenkins-ci.org/browse/JENKINS-25081">issue 25081</a>)
  <li class=bug>
    Updated SSH Slaves plugin to 1.8.
  <li class=bug>
    Due to the reaction, default umask in debian package is set back to 022
    (<a href="https://issues.jenkins-ci.org/browse/JENKINS-25065">issue 25065</a>)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,6 +61,10 @@
   <li class=bug>
     Prevent empty file creation if file parameter is left empty.
     (<a href="https://issues.jenkins-ci.org/browse/JENKINS-3539">issue 3539</a>)
+  <li class=bug>
+    Servlet containers may refuse to let us set <a href="https://www.owasp.org/index.php/SecureFlag">secure cookie flag</a>.
+    Deal with it gracefully.
+    (<a href="https://issues.jenkins-ci.org/browse/JENKINS-25019">issue 25019</a>)
 </ul>
 </div><!--=TRUNK-END=-->
 
```
